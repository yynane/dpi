#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Remove GTP layer from PCAP file'''
import dpkt, struct, time, re, socket
import platform
import sys

# Check for arguments
# if len(sys.argv) < 3 or len(sys.argv) > 3:
#     print "Usage:\n", sys.argv[0], "2017061410592800007011032-tx.pcap", "output.pcap"
#     sys.exit()
# 单独的剥离GTP包头的程序，但是目前只能写入文件，不能内容里面剥离后，直接再处理。

# Open files for input and output
try:
    fi = open('2017061410592800007011032-tx.pcap', 'r')
    fo = open('out.pcap', 'w')

    # Prepare PCAP reader and writter
    pcapin = dpkt.pcap.Reader(fi)
    pcapout = dpkt.pcap.Writer(fo)

    for ts, buf in pcapin:
        # make sure we are dealing with IP traffic
        # ref: http://www.iana.org/assignments/ethernet-numbers
        try: eth = dpkt.ethernet.Ethernet(buf)
        except: continue
        if eth.type != 2048: continue

        # make sure we are dealing with UDP
        # ref: http://www.iana.org/assignments/protocol-numbers/
        try: ip = eth.data
        except: continue
        if ip.p != 17: continue

        # filter on UDP assigned ports for GTP User
        # ref: http://www.iana.org/assignments/port-numbers
        try: udp = ip.data
        except: continue
        try:
            if udp.dport != 2152: continue
        except: continue

        # extract GTP flags to detect header length
        gtpflags = udp.data[:1]
        try:
            if gtpflags == '\x30': payload = udp.data[8:]
            elif gtpflags == '\x32': payload = udp.data[12:]
            else: continue
        except: continue

        # at this point we have a confirmed ETH/IP/UDP/GTP packet structure
        # UDP payload is GTP header + real user payload
        try:
            # append real user payload to ethernet layer and writeout
            eth.data = payload
            pcapout.writepkt(eth, ts)
        except: continue

    fi.close()
    fo.close()

except IOError as (errno, strerror):
    print "I/O error({0}): {1}".format(errno, strerror)