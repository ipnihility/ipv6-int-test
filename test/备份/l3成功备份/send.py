#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, IPv6, UDP
from scapy.fields import *
import readline

from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SourceRoute(Packet):
    fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

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

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IPv6, bos=1)
bind_layers(IPv6, MRI,nh=150)

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    #addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, sys.argv[1])

    while True:
        print
        s = str(raw_input('Type space separated port nums '
                          '(example: "4 3 1 2 2 ") or "q" to quit: '))
        if s == "q":
            break;
        print

        i = 0
        #pkt =  Ether(src=get_if_hwaddr(iface), dst='00:aa:00:00:00:01');
        pkt =  Ether()
        for p in s.split(" "):
            try:
                pkt = pkt / SourceRoute(bos=0, port=int(p))
                i = i+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, i).bos = 1

        pkt = pkt / IPv6(dst=sys.argv[1], nh=150) / MRI(count=0, swtraces=[])
        #pkt = pkt / SwitchTrace(swid=0, in_port=0, out_port=0, qdepth=0, in_time=0, out_time=0, bos=0)
        #pkt = pkt / SwitchTrace(swid=0, in_port=0, out_port=0, qdepth=0, in_time=0, out_time=0, bos=0)
        #pkt = pkt / UDP(dport=4321, sport=1234) / "P4 is cool"
        pkt.show2()
        
        for i in range(int(sys.argv[2])):
            sendp(pkt, iface=iface, verbose=False)
            sleep(1)
        #sendp(pkt, iface=iface, verbose=False)

    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=3);
    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=2);
    #pkt = pkt / SourceRoute(bos=1, port=1)


if __name__ == '__main__':
    main()
