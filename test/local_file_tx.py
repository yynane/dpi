#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: yy
@time: 7/25/17 10:04 PM
"""

#import pcap
import dpkt
import socket
import time
import sys
import struct


def append_hdr(pkt, ts=None, snaplen=1500, linktype=1, nano=False):

    precision = 9 if nano else 6
    # magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    #
    # if sys.byteorder == 'little':
    #     fh = dpkt.pcap.LEFileHdr(snaplen=snaplen, linktype=linktype, magic=magic)
    # else:
    #     fh = dpkt.pcap.FileHdr(snaplen=snaplen, linktype=linktype, magic=magic)

    if ts is None:
        ts = time.time()

    s = bytes(pkt)
    n = len(s)
    sec = int(ts)
    usec = int(round(ts % 1 * 10 ** precision))

    if sys.byteorder == 'little':
        ph = dpkt.pcap.LEPktHdr(tv_sec=sec,
                                tv_usec=usec,
                                caplen=n, len=n)
    else:
        ph = dpkt.pcap.PktHdr(tv_sec=sec,
                              tv_usec=usec,
                              caplen=n, len=n)

    buf = '%s\n%s\n' % (bytes(ph), s)
    return buf

#
# def read_buf(fileobj):
#     name = getattr(fileobj, 'name', '<%s>' % fileobj.__class__.__name__)
#     __f = fileobj
#     buf = __f.read(dpkt.pcap.FileHdr.__hdr_len__)
#     __fh = dpkt.pcap.FileHdr(buf)
#     __ph = dpkt.pcap.PktHdr
#     if __fh.magic in (dpkt.pcap.PMUDPCT_MAGIC, dpkt.pcap.PMUDPCT_MAGIC_NANO):
#         __fh = dpkt.pcap.LEFileHdr(buf)
#         __ph = dpkt.pcap.LEPktHdr
#     elif __fh.magic not in (dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.TCPDUMP_MAGIC_NANO):
#         raise ValueError('invalid tcpdump header')
#     if __fh.linktype in dpkt.pcap.dltoff:
#         dloff = dpkt.pcap.dltoff[__fh.linktype]
#     else:
#         dloff = 0
#     _divisor = 1E6 if __fh.magic in (dpkt.pcap.TCPDUMP_MAGIC, dpkt.pcap.PMUDPCT_MAGIC) else dpkt.pcap.Decimal('1E9')
#     snaplen = __fh.snaplen
#     filter = ''
#     __iter = iter(self)


def strip_off_gtp(buf):

        # make sure we are dealing with IP traffic
        # ref: http://www.iana.org/assignments/ethernet-numbers
        try: eth = dpkt.ethernet.Ethernet(buf)
        except: return 1
        if eth.type != 2048: return 2

        # make sure we are dealing with UDP
        # ref: http://www.iana.org/assignments/protocol-numbers/
        try:ip = eth.data
        except: return 3
        if ip.p != 17: return 4

        # filter on UDP assigned ports for GTP User
        # ref: http://www.iana.org/assignments/port-numbers
        try: udp = ip.data
        except: return 5
        try:
            if udp.dport != 2152: return 6
        except: return 7

        # extract GTP flags to detect header length
        gtpflags = udp.data[:1]
        try:
            if gtpflags == '\x30': payload = udp.data[8:]
            elif gtpflags == '\x32': payload = udp.data[12:]
            else:
                return 8
        except: return 9

        # at this point we have a confirmed ETH/IP/UDP/GTP packet structure
        # UDP payload is GTP header + real user payload
        try:
            # append real user payload to ethernet layer and writeout
            # eth.data = payload
            eth = dpkt.ethernet.Ethernet(data=payload)
            return eth
        except: return 10


def get_http():
    pass


def main(pc):

    # control run time
    runtime = 0

    for ts, pkt in pc:
        # control run times.
        if runtime == 2:
            break
        runtime += 1
        # change time format.
        time_pk = time.strftime('%y-%m-%d %H:%M:%S', time.localtime(ts))

        # strip off gtp header.
        # no_gtp_data = strip_off_gtp(pkt)
        # no_gtp_pkt = append_hdr(no_gtp_data, ts)
        # print(no_gtp_data)
        # print(str(runtime) + "---------------------------------------------------------------")
        # print(no_gtp_pkt)

        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        print(str(runtime) + "---------------------------------------------------------------")
        print("[time:%s]_[src:%s]--->[dst:%s]" % (time_pk, src, dst))


if __name__ == '__main__':
    # common read file
    r_file = open('out.pcap', 'rb')
    pc = dpkt.pcap.Reader(r_file)

    # pcap read file
    # pc1 = pcap.pcap('2017061410592800007011032-tx.pcap')
    # pc2 = pcap.pcap('out.pcap')
    main(pc)
