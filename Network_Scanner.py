#!/usr/bin/env python3

import re
import subprocess
from prettytable import PrettyTable

def validate_ip_range(ip_range):
    """
    Validate the provided IP range in CIDR notation.
    Example of valid input: 192.168.1.0/24
    """
    pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
    if not pattern.match(ip_range):
        print("[-] Invalid IP range. Please provide a valid CIDR (e.g., 192.168.1.0/24).")
        return False

    # Check if IPs and subnet are valid
    ip, subnet = ip_range.split("/")
    octets = ip.split(".")
    if not all(0 <= int(octet) <= 255 for octet in octets) or not (0 <= int(subnet) <= 32):
        print("[-] Invalid IP range. Please provide a valid CIDR (e.g., 192.168.1.0/24).")
        return False

    return True


def scan_network(ip_range):
    """
    Run nmap to scan the network and retrieve the results.
    """
    print("[*] Scanning network using nmap...")
    try:
        result = subprocess.check_output(["nmap", "-sn", ip_range], universal_newlines=True)
        return result
    except Exception as e:
        print(f"[-] Error running nmap: {e}")
        return None


def parse_nmap_output(nmap_output):
    """
    Parse nmap output to extract IP, MAC, and hostname details.
    """
    print("[*] Parsing nmap output...")
    devices = []
    if not nmap_output:
        return devices

    lines = nmap_output.splitlines()
    current_device = {}

    for line in lines:
        line = line.strip()
        if "Nmap scan report for" in line:
            if current_device:  # Save the previous device
                devices.append(current_device)
            current_device = {"ip": None, "mac": None, "hostname": None}
            parts = line.split(" ")
            if len(parts) >= 4:  # Has hostname and IP
                current_device["hostname"] = parts[3].strip("()")
                current_device["ip"] = parts[-1].strip("()")
            else:  # Only IP
                current_device["ip"] = parts[3].strip("()")
        elif "MAC Address:" in line:
            parts = line.split("MAC Address: ")
            mac_info = parts[1].split(" ")
            current_device["mac"] = mac_info[0]

    # Add the last device
    if current_device:
        devices.append(current_device)

    return devices


def print_results(devices):
    """
    Print the results in a table format.
    """
    print("[*] Displaying results...")
    if not devices:
        print("[-] No devices found on the network.")
        return

    table = PrettyTable(["IP", "MAC Address", "Hostname"])
    table.align = "l"

    for device in devices:
        ip = device["ip"] if device["ip"] else "Unknown"
        mac = device["mac"] if device["mac"] else "Unknown"
        hostname = device["hostname"] if device["hostname"] else "N/A"
        table.add_row([ip, mac, hostname])

    print(table)


if __name__ == "__main__":
    target_range = input("Enter the target IP range (e.g., 192.168.1.0/24): ").strip()
    if validate_ip_range(target_range):
        nmap_result = scan_network(target_range)
        devices = parse_nmap_output(nmap_result)
        print_results(devices)
