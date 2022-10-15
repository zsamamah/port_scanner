#!/usr/bin/python

import optparse
from socket import *
from threading import *


def scan_port(host, port):
    sock = socket(AF_INET, SOCK_STREAM)
    if sock.connect_ex((host, int(port))):
        print('[-] {}/tcp closed'.format(port))
    else:
        print('[+] {}/tcp open'.format(port))
    sock.close()


def scan_host(host, ports):
    try:
        tgt_ip = gethostbyname(host)
    except:
        print('[-] Can`t resolve host name')
        exit(0)
    try:
        host_name = gethostbyaddr(tgt_ip)
        print "-> Scan results for :" + str(host_name[0])
    except:
        print "> Scan results for :" + tgt_ip
    for port in ports:
        thread = Thread(target=scan_port, args=(host, port))
        thread.start()


def main():
    parser = optparse.OptionParser('Usage Of Program :\n' + '-H <target host> \n' + '-p <target ports>')
    parser.add_option('-H', dest='tgtHost', type='string', help='Specify target host')
    parser.add_option('-p', dest='tgtPorts', type='string', help='Specify target ports separated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPorts).split(',')
    if (tgtHost is None) or (tgtPorts[0] == 'None'):
        print(parser.usage)
        exit(0)
    else:
        scan_host(tgtHost, tgtPorts)


if __name__ == '__main__':
    main()

