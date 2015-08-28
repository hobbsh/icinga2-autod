#!/usr/bin/env python
import sys
import subprocess
import argparse
import nmap
import time

"""
This discovery script will scan a subnet for alive hosts, 
determine some basic information about them,
then create a hosts.conf in the current directory for use in Nagios or Icinga

required Linux packages: python-nmap and nmap

Wylie Hobbs - 08/28/2015
"""

def build_parser():

    parser = argparse.ArgumentParser(description='Device AutoDiscovery Tool')

    parser.add_argument('-n', '--network',
	help='Network segment (only /24) to iterate through for live IP addresses in CIDR IPv4 Notation')

    parser.add_argument('-l', '--location',
        help='Location alias of the network - will be appended to the hosts config (i.e. hosts_location.conf)')

    return parser

def main():

    parser = build_parser()
    args = parser.parse_args()
    start_time = time.time()

    cidr = args.network
    location = args.location

    credential = dict()
    credential['version'] = '2c'
    credential['community'] = ['public', 'private']

    #Hostname and sysDescr OIDs
    oids = '.1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.1.0'

    #Scan the network
    nm = handle_netscan(cidr)

    all_hosts = {}

    print("Found {0} hosts - gathering more info (can take up to 2 minutes)".format(get_count(nm.all_hosts())))

    for host in nm.all_hosts():
	host = str(host)

	'''If your communities/versions vary, modify credentials here. I've used last_octet to do this determination
	        octets = host.split('.')
                last_octet = str(octets[3]).strip()
	   Otherwise, grab the data
	'''

	data = snmpget_by_cl(host, credential, oids)
	output = data['output'].split('\n')

	try:
	    hostname = output[0]
	    sysdesc = output[1]
	except:
	    hostname = ''
	    sysdesc = ''
	
	all_hosts[host] = { 
	    'community': data['community'], 'snmp_version': credential['version'], 'hostname': hostname, 'sysdesc': sysdesc }

    print "\n"
    print("Discovery took %s seconds" % (time.time() - start_time))
    print "Writing data to config file. Please wait"

    outfile = compile_hosts(all_hosts, location)
    print "Wrote data to "+outfile

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
	    '  host.vars.location == "%s"\n'
	    '  %s\n'
	    '}\n' % (hostname, str(ip), str(location), str(hostvars))
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
	'RouterOS': 'host.vars.network_mikrotik', 
	'Linux':'host.vars.os == "Linux"', 
	'APC Web/SNMP': 'host.vars.ups_apc', 
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
    nm = nmap.PortScanner()
    nm.scan(hosts=cidr, arguments='-sn -sP')
    
    print ("Scan took %s seconds" % (time.time() - start))

    return nm


def snmpget_by_cl(host, credential, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpget method from net-snmp source to loop through multiple communities if necessary
    '''

    data = {}
    version = credential['version']
    community = credential['community']
    com_count = len(community)

    for i in range(0, com_count):
	cmd = ''
	community = credential['community'][i]
        cmd = "snmpget -Oqv -v %s -c %s -r %s -t %s %s %s" % (
            version, community, retries, timeout, host, oid)
	
	returncode, output, err = exec_command(cmd)

        if returncode and err:
	    if i < com_count:
	        continue	
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
