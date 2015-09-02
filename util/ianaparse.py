#!/usr/bin/python
#
# iana_enterprise_numbers_convert.py
# a script to convert the IANA "enterprise-numbers" to a JSON file
#
# Ch. Bueche <bueche@netnea.com>
# 22.7.2014
#
# https://raw.githubusercontent.com/cbueche/Agent-Jones/master/util/iana_enterprise_numbers_convert.py
#
# Modified for use in icinga-autod.py 
#

import sys
import os
import re
import json
import urllib2
import tempfile

class IanaParser(object):
    # --------------------------------------------------------------------------------
    def parse(self):
    # --------------------------------------------------------------------------------
    
        # script parameters
        input_url = 'http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers'
        output_file = 'iana_numbers.json'
    
        global debug
        debug = False
    
        temp_file = self.get_from_url(input_url)
        if debug:
            print "IF=<%s>, TMP=<%s>, OUT=<%s>" % (input_url, temp_file, output_file)
    
        # conversion
        entries = self.iana_to_json(temp_file, output_file)
        #print "found %s entries" % entries
        if debug:
            print "deleting tmp file %s" % temp_file
        os.unlink(temp_file)
        #print "End"
	return entries
    
    
    # --------------------------------------------------------------------------------
    def iana_to_json(self, temp_file, output_file):
    # --------------------------------------------------------------------------------
    
        # temp file
        try:
            fp = open(temp_file, 'r')
        except (IOError, OSError) as e:
            print "ERROR : cannot open input file, exit : %s" % e
            sys.exit(1)
    
        # header parsing
        # --------------
    
        # read until the data start (0 - Reserved)
        while True:
            line = fp.readline()
            if not line: break
    
            # remove end of line
            line = line.rstrip()
    
            # check for the usual IANA header in 1st line
            if re.search(r'PRIVATE ENTERPRISE NUMBERS', line):
                if debug:
                    print "found header"
    
            # last updated stamp
            regex = re.compile(r'\(last updated (\d{4}-\d{2}-\d{2})\)')
            match = regex.search(line)
            if match:
                last_update = match.group(1)
                #print "updated = %s" % last_update
    
            # stop right before the data records
            if line == '| | | |':
                break
    
        if debug:
            print "header done"
    
        # and now the data
        # -------------------------------------
    
        valid_entries = 0
        enterprises = {}
        block = []
        while True:
    
            line = fp.readline().strip('\n')
    
            # skip blank lines
            if line == '':
                continue
    
            # try to extract a record
            # idea is to read from one decimal to the next
            # and send the read block to a function to parse it
    
            # get decimal
            if re.search(r'^\d+$', line):
                # before creating the new block, send the existing one to analysis
                # skip the first, empty block
                if len(block) > 0:
                    valid_entries += 1
                    status, decimal, organization, contact, email = self.analyze_block(block)
                    if status:
                        enterprises[decimal] = {'o': organization, 'c': contact, 'e': email}
                # and now start a new block
                block = []
                decimal = line.strip()
                block.append(decimal)
    
            else:
    
                # now add to current block until next decimal
                block.append(line)
    
            # check for the usual IANA footer in last line
            if re.search(r'End of Document', line):
                # and stores the last found block
                block.pop()
                valid_entries += 1
                status, decimal, organization, contact, email = self.analyze_block(block)
                if status:
                    enterprises[decimal] = {'o': organization, 'c': contact, 'e': email}
    
                if debug:
                    print "found footer, exit read loop"
                break
    
        fp.close
        # write data structure to output file
        with open(output_file, 'w') as of:
          json.dump(enterprises, of)

        return enterprises
    
    
    # --------------------------------------------------------------------------------
    def analyze_block(self, block):
    # --------------------------------------------------------------------------------
    
        if debug:
            print "analyzing block %s" % block
    
        decimal = 0
        organization = ''
        contact = ''
        email = ''
    
        # first element must be the decimal number. If not, we are doing something wrong
        if re.search(r'^\d+$', block[0]):
            decimal = block[0]
        else:
            print "ERROR: first element of block is not a valid decimal"
            return False, -1, 'na', 'na', 'na'
    
        # now loop over the other elements
        last_element_found = ''
        for element in block[1:]:
            if debug:
                print "working on element <%s>" % element
    
            # get line addition
            # any non-blank text starting at beginning of line, but not a number
            if re.search(r'^[^\d\s]', element):
                if debug:
                    print "line continuation"
                if last_element_found == 'organization':
                    organization = organization + ' ' + element
                elif last_element_found == 'contact':
                    contact = contact + ' ' + element
                elif last_element_found == 'email':
                    email = email + ' ' + element
                else:
                    print "ERROR: don't know how to add this line to unknown block element"
                    return False, -1, 'na', 'na', 'na'
                continue
    
            # organization
            if last_element_found == '':
                organization = element
                last_element_found = 'organization'
                continue
    
            # contact
            if last_element_found == 'organization':
                contact = element
                last_element_found = 'contact'
                continue
    
            # email
            if last_element_found == 'contact':
                email = element.replace('&', '@')
                last_element_found = 'email'
                continue
    
            # something after email, shall not happen
            if last_element_found == 'email':
                print "ERROR: nothing should come after the email element"
                continue
    
        return True, decimal, self.clean(organization), self.clean(contact), self.clean(email)
    
    
    # --------------------------------------------------------------------------------
    def clean(self, input):
    # --------------------------------------------------------------------------------
    
        output = input.strip()
        output = re.sub(r'\s+', ' ', output)
        return output
    
    
    # --------------------------------------------------------------------------------
    def get_from_url(self, url):
    # --------------------------------------------------------------------------------
    
        tmp = tempfile.NamedTemporaryFile(prefix = 'iana_en_', suffix = '.tmp', delete = False)
        urldata = urllib2.urlopen(url)
        while True:
            line = urldata.readline()
            if not line: break
            tmp.write(line)
    
        tmp.close()
        return tmp.name 

