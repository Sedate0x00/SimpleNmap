#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : Sedate

import sys
import getopt
import nmap

hosts = ''
output = False
nm = None


def port_scan():
    nm.scan(hosts=hosts, arguments='-Pn -sV -O')

    for host in nm.all_hosts():
        print '\n----------------------------------------------------'
        print 'Host : %s (%s)' % (host, nm[host].hostname())
        print 'State : %s' % nm[host].state()
        for proto in nm[host].all_protocols():
            print '\nProtocol : %s' % proto
            lport = nm[host][proto].keys()
            lport.sort()
            print '\nport   state   product   version'
            for port in lport:
                print '%s   %s   %s   %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['product'],
                                             nm[host][proto][port]['version'])
        print '\nos'
        for os in nm[host]['osmatch']:
            print '%s(%s%%)' % (str(os['osclass'][0]['cpe'][0]), str(os['osclass'][0]['accuracy']))
        print '----------------------------------------------------\n'


def xml_out():
    f = open('%s.xml' % hosts.replace('/', '_'), 'w')
    f.write(nm._nmap_last_output)
    f.close()
    print 'result xml output success...in same directory\n'


def usage():
    print 'usage:portscan.py -h host -o'
    print '-h host ip'
    print '-o output xml file'
    sys.exit(0)


def main():
    global hosts
    global output
    global nm

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h:o', ['host=', 'output'])
    except Exception as e:
        print e
        usage()

    for o, a in opts:
        if o in ('-h', '--host'):
            hosts = a
        elif o in ('-o', '--output'):
            output = True
        else:
            usage()

    if hosts:
        nm = nmap.PortScanner()
        port_scan()
    else:
        usage()

    if output == True:
        xml_out()


if __name__ == '__main__':
    main()
