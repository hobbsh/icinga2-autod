#!/usr/bin/env python

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

    ret, out, err = exec_command('which '+package)

    if not ret and err:
        return [package, True]
    else:

        distro = platform.dist()[0].lower()

        #Debian or RedHat based?
        if distro in ['centos', 'redhat']:
            if package == 'snmp':
                command = 'rpm -qa | grep -e ^net-snmp-[0-9].*$'
            elif package == 'python-nmap':
		command = '[ -d "/usr/share/doc/python-nmap" ] && echo "Installed"'
            else:
                command = 'rpm -qa | grep -e '+package

            ret, out, err = exec_command(command)

        elif distro in ['ubuntu', 'debian']:
            ret, out, err = exec_command("dpkg --list | awk '{print $2}' | grep -e ^"+package+"$")

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

