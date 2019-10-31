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

import time


def main():
    with open('flag.txt', 'r') as f:
        i = int(f.readline())
    print i


if __name__ == '__main__':
    main()
