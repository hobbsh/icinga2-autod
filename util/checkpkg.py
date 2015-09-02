#!/usr/bin/env python
'''
This module checks for the existence of a given package on the host OS
Currently only RHEL/Debian based systems supported

Usage: 
import checkpkg
checkpkg.check(['package1', 'package2', 'package3'])

Note that this is not completely universal and customizations for some packages might need to be added

Copyright Wylie Hobbs 2015

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

'''
import subprocess
import os
import platform
import sys

def check(packages):

    dependencies = True

    for package in packages:
        pkg, installed =  _find(package)
        if not installed:
            sys.stderr.write('Package '+package+' is not installed! Please install it and try again\n')
            dependencies = False

    if dependencies:
        return
    else:
        sys.exit(1)

def _find(package):
    
    #Try with which first
    ret, out, err = exec_command('which '+package)

    if not ret and err:
        return [package, True]
    else:

	#Get distro name
        distro = platform.dist()[0].lower()

        #Debian or RedHat based?
        if distro in ['centos', 'redhat']:
            if package == 'snmp':
                command = 'rpm -qa | grep -e ^net-snmp-[0-9].*$'
            else:
                command = 'rpm -qa | grep -e '+package

            ret, out, err = exec_command(command)

        elif distro in ['ubuntu', 'debian']:
            ret, out, err = exec_command("dpkg --list | awk '{print $2}' | grep -e ^"+package+"$")

	else:
	    sys.stderr.write('Unsupported distribution! You will have to resolve missing requirements yourself.')
	    sys.exit(1)

        if len(out) > 0:
            return [package, True]
        else:
            return [package, False]


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

