#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, IPv6, UDP, Raw, Ether
#from influxdb import InfluxDBClient
import requests
import time

"""
sx_time = [0, -1700, -890]
sx_flag = 0
temp = 0
"""

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ BitField("swid", 0, 8),
                  BitField("in_port", 0, 8),
                  BitField("out_port", 0, 8),
                  ShortField("in_qdepth", 0),
                  ShortField("out_qdepth", 0),
                  BitField("in_time", 0, 48),
                  BitField("queue_time", 0, 32),
                  IntField("ingress_pkt_cnt", 0),
                  IntField("ingress_byte_cnt", 0),
                  IntField("ingress_drop_cnt", 0),
                  IntField("egress_pkt_cnt", 0),
                  IntField("egress_byte_cnt", 0),
                  IntField("egress_drop_cnt", 0)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
    fields_desc = [FieldLenField("length", None,
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*41+4),
                  ShortField("count", 0),
                  PacketListField("swtraces",
                                  [],
                                  SwitchTrace,
                                  count_from=lambda pkt:(pkt.count*1))]

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IPv6, bos=1)
bind_layers(IPv6, MRI, nh=150)
bind_layers(MRI, UDP)

"""
def sw_info(swname, depth):
    data_list = [{'measurement': 'swinfo',
                  'tag': {'sw': swname},
                  'fields': {'qdepth': depth}}]
    return data_list
"""

def handle_pkt(pkt):
    global sx_flag
    global temp
    print "-----------------------"
    print "-----------------------"
    pkt.show2()
#    hexdump(pkt)
"""
    sys.stdout.flush()
    s1 = "curl -i -XPOST \"http://localhost:8086/write?db=switch\" --data-binary \'swinfo,sw="
    s = ["in_qdepth=", "out_qdepth=", "in_time=", "queue_time=", "ingress_pkt=", "ingress_byte=", "egress_pkt=", "egress_byte="]
    influxdb_time = " " + str(int(time.time() * 1000)) + "000000" + "\'"
    for swinfo in reversed(pkt[MRI].swtraces):
        if(sx_flag == 0):
            sx_time[swinfo.swid - 1] = sx_time[swinfo.swid - 1] + swinfo.in_time
        q = []
        sw = 's' + str(swinfo.swid)
        q.append(str(swinfo.in_qdepth) + ',')
        q.append(str(swinfo.out_qdepth) + ',')
        q.append(str(swinfo.in_time - sx_time[swinfo.swid - 1] - temp) + ',')
        temp = swinfo.in_time - sx_time[swinfo.swid - 1]
        q.append(str(swinfo.queue_time) + ',')
        q.append(str(swinfo.ingress_pkt_cnt) + ',')
        q.append(str(swinfo.ingress_byte_cnt) + ',')
        q.append(str(swinfo.egress_pkt_cnt) + ',')
        q.append(str(swinfo.egress_byte_cnt))
        str1 = s1 + sw + " "
        for i in range(8):
            str1 = str1 + s[i] + q[i]
        str1 = str1 + influxdb_time
        str2 = "./insert/" + sw + "info.txt"
        #print str1
        #print str2
        with open(str2, 'a') as f:
            f.write(str1 + '\n')
            sys.stdout.flush()
            #print str1
        print sw + " : in_qdepth " + str(swinfo.in_qdepth)
        print sw + " : out_qdepth " + str(swinfo.out_qdepth)
        print sw + " : queue_time " + str(swinfo.queue_time)
        print sw + " : in_time " + str(swinfo.in_time - sx_time[swinfo.swid - 1])
        print sw + " : egress_pkt_cnt " + str(swinfo.egress_pkt_cnt)
    if(sx_flag == 0):
        sx_flag = 1
"""


def main():
    #client = InfluxDBClient('10.15.97.194', 8086, 'admin', 'rocks', 'switch')
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="ip6 and proto 150", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
