#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@version: 
@author: yuying
@time: 2017/07/25
测试解析爱立信提供的数据包2017071710022100001011032和2017061410592800007011032-tx（腾讯测试）。
"""

import socket
import dpkt


def mytest():

    r_file = open('2017061410592800007011032-tx.pcap', 'r')
    pc = dpkt.pcap.Reader(r_file)

    for ts, pkt in pc:
        print ts,pkt
        # try:
        #     eth = dpkt.ethernet.Ethernet(pkt)
        #     ip = eth.data
        #     src = socket.inet_ntoa(ip.src)
        #     dst = socket.inet_ntoa(ip.dst)
        #     print "[time:%s]_[src:%s]--->[dst:%s]" % (ts, src, dst)
        #     print "---------------------------------------------------------------"
        #     udp = dpkt.udp.UDP(pkt)
        #     udp_data = udp.unpack(pkt)
        #     print udp
        # except:
        #     pass


mytest()
