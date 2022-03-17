#!/usr/bin/python3

import socket

ips = {}

def load_hostnames(filename):
    infile = open(filename, 'r')
    trimmed = map(lambda r: r.rstrip(), infile)
    without_blanks = filter(lambda r: r, trimmed)
    return without_blanks

def output_routes(filename):
    global ips
    with open(filename, 'w') as outfile:
        for ip in sorted(ips.keys()):
            outfile.write(f"route {ip}/32 unreachable; # {ips[ip]}\n")


hostnames = list(load_hostnames('force-include-hostnames.txt'))

for host in hostnames:
    try:
        res = socket.gethostbyname_ex(host)
        for ip in res[2]:
            hnames = ips.get(ip, '')
            if hnames:
                hnames += ', '
            hnames += host
            ips[ip] = hnames
    except BaseException:
        pass

if len(ips) > 0:
    output_routes('.hostname.routes')
