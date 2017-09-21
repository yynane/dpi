#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: yuying
@time: 2017/9/20 15:17
"""

#!/usr/bin/env python

import dpkt

f = open('out.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    if tcp.dport == 80 and len(tcp.data) > 0:
        http = dpkt.http.Request(tcp.data)
        print(http.uri)

f.close()