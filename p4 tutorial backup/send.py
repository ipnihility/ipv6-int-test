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

MAX_t = 1

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

class Bitmap(Packet):
    fields_desc = [ BitField("bit_label", 0, 8),
                   BitField("bit_reserve", 0, 8)]

class SwitchTrace1(Packet):
    fields_desc = [ BitField("swid", 0, 8),
                  BitField("in_port", 0, 8),
                  BitField("out_port", 0, 8),
                  BitField("in_time", 0, 48)]
    def extract_padding(self, p):
                return "", p

class MRI1(Packet):
    fields_desc = [FieldLenField("length", None,
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*9+4),
                  ShortField("count", 0),
                  PacketListField("swtraces",
                                  [],
                                  SwitchTrace1,
                                  count_from=lambda pkt:(pkt.count*1))]

class SwitchTrace2(Packet):
    fields_desc = [ BitField("swid", 0, 8),
                  BitField("in_port", 0, 8),
                  BitField("out_port", 0, 8),
                  ShortField("in_qdepth", 0),
                  ShortField("out_qdepth", 0),
                  BitField("in_time", 0, 48),
                  BitField("out_time", 0, 48),
                  BitField("queue_time", 0, 32)]
    def extract_padding(self, p):
                return "", p

class MRI2(Packet):
    fields_desc = [FieldLenField("length", None,
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*23+4),
                  ShortField("count", 0),
                  PacketListField("swtraces",
                                  [],
                                  SwitchTrace2,
                                  count_from=lambda pkt:(pkt.count*1))]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IPv6, bos=1)
bind_layers(IPv6, Bitmap, nh=150)
bind_layers(Bitmap, MRI1, bit_label=228)
bind_layers(Bitmap, MRI2, bit_label=255)

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    #addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, sys.argv[1])

    print
    s = str(raw_input('Type space separated port nums '
                      '(example: "4 3 1 2 2 ") or "q" to quit: '))
    if s == "q":
        exit(1)
    print

    i = 0
    pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:02:02')
    
    for p in s.split(" "):
        try:
            pkt = pkt / SourceRoute(bos=0, port=int(p))
            i = i+1
        except ValueError:
            pass
    if pkt.haslayer(SourceRoute):
        pkt.getlayer(SourceRoute, i).bos = 1
    

    #pkt = pkt / IPv6(dst=sys.argv[1], nh=150) / Bitmap(bit_label=228, bit_reserve=0) / MRI1(count=0, swtraces=[])
    pkt = pkt / IPv6(dst=sys.argv[1], nh=150)
    
    
    while True:
        '''with open('flag.txt', 'r') as f:
            t = float(f.readline())
        if (t != MAX_t):
            p = pkt / Bitmap(bit_label=255, bit_reserve=0) / MRI1(count=0, swtraces=[])
        else:
            p = pkt / Bitmap(bit_label=228, bit_reserve=0) / MRI2(count=0, swtraces=[])'''
        p = pkt / Bitmap(bit_label=255, bit_reserve=0) / MRI1(count=0, swtraces=[])
        p.show2()
        sendp(p, iface=iface, verbose=False)
        #sleep(t)
        sleep(1)


if __name__ == '__main__':
    main()
