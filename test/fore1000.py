#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: yuying
@time: 2017/9/19 14:24
协助王旭东提取前1000个字节的数据
"""


import dpkt


def main(pc):

    # control run time
    runtime = 0

    for ts, pkt in pc:
        # control run times.
        runtime += 1
        if runtime == 10:
            break
        a = pkt[:1000]
        print(a)
        print('---------------')


if __name__ == '__main__':
    # common read file
    r_file = open('2017061410592800007011032-tx.pcap', 'rb')
    pc = dpkt.pcap.Reader(r_file)

    main(pc)
