#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: yuying
@time: 2017/9/20 9:19
单独解析HTTP的测试程序
目前问题，许多是二进制数据，没正常解析
"""


import dpkt
import socket
import time


def main(pc):

    # control run time
    runtime = 0

    for ts, pkt in pc:
        # control run times.
        if runtime == 35150:
            break
        runtime += 1
        # change time format.
        time_pk = time.strftime('%y-%m-%d %H:%M:%S', time.localtime(ts))

        eth = dpkt.ethernet.Ethernet(pkt)
        ip_data = eth.data
        src = socket.inet_ntoa(ip_data.src)
        dst = socket.inet_ntoa(ip_data.dst)
        tcp_data = ip_data.data
        app_data = tcp_data.data
        try:
            sport = tcp_data.sport
            dport = tcp_data.dport
            http = dpkt.http.Request(app_data)
            if 'qq.com' in http.headers['host']:
                print(str(runtime) + "---------------------------------------------------------------")
                print('[time]:',  time_pk)
                print('[原始TCP报文]:', tcp_data)
                print('[srcIP和端口]:%s,%s' % (src, sport))
                print('[dstIP和端口]:%s,%s' % (dst, dport))
                print('[原始HTTP报文]:', app_data)
                print('[原始HTTP包头]:', http.headers)
                if 'host' in http.headers:
                    print('[HOST]:', http.headers['host'])
                print('[URL]:', http.uri)
                if 'accept-encoding' in http.headers:
                    print('[accept-encoding]:', http.headers['accept-encoding'])
                print('[Body]:', http.body)
        except Exception as e:
            print('%s:%s' % (runtime, e))



if __name__ == '__main__':
    # common read file
    r_file = open('out.pcap', 'rb')
    pc = dpkt.pcap.Reader(r_file)
    # pcap read file
    # pc1 = pcap.pcap('2017061410592800007011032-tx.pcap')
    # pc2 = pcap.pcap('out.pcap')
    main(pc)