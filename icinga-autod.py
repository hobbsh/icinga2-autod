#!/usr/bin/env python
import util.checkpkg as checkpkg

checkpkg.check(['nmap', 'snmp', 'net-snmp-utils'])

import sys
import subprocess
import json

try:
    import argparse
except ImportError:
    checkpkg.check(['python-argparse'])

import time
import socket
import util.ianaparse as ianaparse

"""
This discovery script will scan a subnet for alive hosts, 
determine some basic information about them,
then create a hosts.conf in the current directory for use in Nagios or Icinga

required Linux packages: python-nmap and nmap

Copyright Wylie Hobbs - 08/28/2015

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

USAGE = './icinga-autod.py -n 192.168.1.0/24 -L LOCATION'

def build_parser():

    parser = argparse.ArgumentParser(description='Device AutoDiscovery Tool')

    parser.add_argument('-n', '--network',
	help='Network segment (only /24) to iterate through for live IP addresses in CIDR IPv4 Notation')

    parser.add_argument('-L', '--location',
        help='Location alias of the network - will be appended to the hosts config (i.e. hosts_location.conf)')

    parser.add_argument('-c', '--communities', default="public,private",
        help='Specify comma-separated list of SNMP communities to iterate through (to override default public,private)')

    parser.add_argument('-d', '--debug', default=False,
        help='Specify comma-separated list of SNMP communities to iterate through (to override default public,private)')

    #The following two arguments have no effect currently
    parser.add_argument('-r', '--reparse-iana', default=False,
        help='Whether icinga-autod should grab a fresh version of the sysObjectIDs from the IANA URL')

    parser.add_argument('-t', '--thorough', default=0,
        help='Thorough scan mode (will take longer) - will try additional SNMP versions/communities to try to gather as much information as possible')

    return parser

def main():

    global debug

    parser = build_parser()
    args = parser.parse_args()

    '''Check arguments'''    
    if check_args(args) is False:
	sys.stderr.write("There was a problem validating the arguments supplied. Please check your input and try again. Exiting...\n")
	sys.exit(1)

    if args.debug:
        debug = True
    else:
	debug = False
    
    start_time = time.time()

    cidr = args.network
    location = args.location

    credential = dict()
    credential['version'] = '2c'
    credential['community'] = args.communities.split(',')

    #Hostname and sysDescr OIDs
    oids = '1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.2.0'

    #Scan the network
    hosts = handle_netscan(cidr)

    all_hosts = {}

    print("Found {0} hosts - gathering more info (can take up to 2 minutes)".format(get_count(hosts)))

    try:
	with open('iana_numbers.json', 'r') as f:
	    numbers = json.load(f)
    except Exception, e:
	try:
    	    numbers = ianaparse.IanaParser().parse()
	except:
	    sys.exit("Unable to open iana_numbers.json or read from the URL. Exiting...")

	sys.stderr.write('Unable to open iana_numbers.json, trying URL method. Please wait\n')


    for host in hosts:
	host = str(host)

	'''If your communities/versions vary, modify credentials here. I've used last_octet to do this determination
	        octets = host.split('.')
                last_octet = str(octets[3]).strip()
	   Otherwise, grab the data
	'''

	data = snmpget_by_cl(host, credential, oids)

	'''TODO: clean up this logic...'''
	try:
	    output = data['output'].split('\n')
	    community = data['community']
	except:
	    community = 'unknown'
	    output = ''

	if output:
	    hostname = output[0].strip('"')
	    sysdesc = output[1].strip('"')
	    sysobject = output[2].strip('"')
	else:
	    hostname = ''
	    sysdesc = ''
	    sysobject = ''
	
	v_match = vendor_match(numbers, sysobject)	

	if v_match:
	    vendor = v_match['o'].strip('"')
	else:
	    vendor = 'NA'
	    
	all_hosts[host] = { 
	    'community': community, 'snmp_version': credential['version'], 'hostname': hostname, 'sysdesc': sysdesc, 'vendor' : vendor }

	if debug:
	    print host, sysobject, all_hosts[host]

    print "\n"
    print("Discovery took %s seconds" % (time.time() - start_time))
    print "Writing data to config file. Please wait"

    outfile = compile_hosts(all_hosts, location)
    print "Wrote data to "+outfile

def vendor_match(numbers, sysobject):
    if sysobject:
	#Possible prefixes in sysObjectID OID largely dependent on MIB used
	prefixes = ['SNMPv2-SMI::enterprises.', 'iso.3.6.1.4.1.', '1.3.6.1.4.1.', 'NET-SNMP-MIB::netSnmpAgentOIDs.']
	
	for prefix in prefixes:
	    if sysobject.startswith(prefix):
	        sysobject = sysobject[len(prefix):]
	
	values = sysobject.split('.')
	#first value will be the enterprise number
	vendor_num = values[0]

	try:
	    vendor_string = numbers[vendor_num]
	    return vendor_string

	except Exception, e:
	    sys.stderr.write('Unknown sysObjectID prefix encountered - you can add it to the prefix list in vendor_match(), but please report this on GitHub\n'+str(e))
	    return False
    else:
	return False

def check_args(args):
    '''Exit if required arguments not specified'''
    if args.network == None or args.location == None:
	sys.stderr.write("Network and/or location are required arguments! Use -h for help\n")
	sys.exit(1)

    check_flags = {}
    '''Iterate through specified args and make sure input is valid. TODO: add more flags'''
    for k,v in vars(args).iteritems():
        if k == 'network':
	    network = v.split('/')[0]
	    if len(network) > 7:
	    	if is_valid_ipv4_address(network) is False:
		    check_flags['is_valid_ipv4_address'] = False
	    else:	
		check_flags['is_valid_ipv4_format'] = False
		
    last_idx = len(check_flags) - 1
    last_key = ''

    '''Find last index key so all the violated flags can be output in the next loop'''
    for idx, key in enumerate(check_flags):
	if idx == last_idx:
	    last_key = key
	
    for flag, val in check_flags.iteritems():
        if val is False:
	    sys.stderr.write("Check "+flag+" failed to validate your input.\n")
	    if flag == last_key:
		return False 

def is_valid_ipv4_address(address):
    '''from http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python'''
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def get_count(hosts):
    count = len(hosts)
    if count == 0:
	print "No hosts found! Is the network reachable? \nExiting..."
	sys.exit(0)
    else:
        return count

def compile_hosts(data, location):
    loc = location.lower()
    
    filename = 'hosts_'+loc+'.conf'
    f = open(filename, 'w')

    for ip, hdata in data.iteritems():
	hostvars = compile_hvars(hdata['sysdesc'])
	hostname = determine_hostname(hdata['hostname'], ip, loc, hostvars)
        host_entry = (
	    'object Host "%s" {\n'
	    '  import "generic-host"\n'
	    '  address = "%s"\n\n'
	    '  #Custom Variables\n'
	    '  vars.location = "%s"\n'
	    '  vars.vendor = "%s"\n'
	    '  %s\n'
	    '}\n' % (hostname, str(ip), str(location), str(hdata['vendor']), str(hostvars))
	)

	f.write(host_entry)

    f.close()

    return filename

def determine_hostname(hostname, ip, loc, hostvars):
    ''' if host does not have a valid or any hostname, try to create one '''
    if len(hostname.split('.')) > 1:
	'''has valid hostname for my environment'''
	return hostname
    else:
	if hostname:
	    if 'mikrotik' in hostvars:
		hostname = 'router.'+loc

	    return hostname

	else:
	    return ip
		
	
def compile_hvars(sysdesc):
    sys_descriptors = {
	'RouterOS': 'vars.network_mikrotik = "true"', 
	'Linux':'vars.os = "Linux"', 
	'APC Web/SNMP': 'vars.ups_apc = "true"', 
    }

    hostvars = ''

    '''Append hostvars based on sysDescr matches'''
    for match, var in sys_descriptors.iteritems():
	if match in sysdesc:
	    hostvars += var +'\n  '

    return hostvars

def handle_netscan(cidr):
    '''
    Scan network with nmap using ping only
    '''
    start = time.time()
    '''
    nm = nmap.PortScanner()
    nm.scan(hosts=cidr, arguments='-sn -sP')
    
    print ("Scan took %s seconds" % (time.time() - start))
    '''
    ret, output, err = exec_command('nmap -sn -sP {0}'.format(cidr))
    if ret and err:
        sys.stderr.write('There was a problem performing the scan - is the network reachable?')
	sys.exit(1)
    else:
	data = parse_nmap_scan(output)
	if data:
	    return data
	else:
	   sys.stderr.write('Unable to parse nmap scan results! Please report this issue')
	   sys.exit(1)

def parse_nmap_scan(data):
    data_list = data.split('\n')
    match = 'Nmap scan report for '
    hosts = []

    for line in data_list:
        if match in line and line is not None:
	    line = line[len(match):].strip(' ')
	    hosts.append(line)

    return hosts

def snmpget_by_cl(host, credential, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpget method from net-snmp source to loop through multiple communities if necessary
    '''

    data = {}
    version = credential['version']
    communities = credential['community']
    com_count = len(communities)

    for i in range(0, com_count):
	cmd = ''
	community = communities[i].strip()
        cmd = "snmpget -Oqv -v %s -c %s -r %s -t %s %s %s" % (
            version, community, retries, timeout, host, oid)
	
	returncode, output, err = exec_command(cmd)
	
	#print returncode, output, err
        if returncode and err:
	    if i < com_count:
	        continue	
	    else:
		data['error'] = str(err)
	else:
	    try:
	        data['output'] = output
	        data['community'] = community
		#Got the data, now get out
		break	
	    except Exception, e:
		print "There was a problem appending data to the dict " + str(e)

    return data

def exec_command(command):
    """Execute command.
       Return a tuple: returncode, output and error message(None if no error).
    """
    sub_p = subprocess.Popen(command,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    output, err_msg = sub_p.communicate()
    return (sub_p.returncode, output, err_msg)


if __name__ == "__main__":
    main()
    sys.exit(0)
