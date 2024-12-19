#!/usr/bin/env python3

import subprocess
import optparse
import re
import random

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    (options, args) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    return options

def generate_random_mac():
    mac = [0x02, 0x00, 0x00,  # Locally administered address
           random.randint(0x00, 0xFF),
           random.randint(0x00, 0xFF),
           random.randint(0x00, 0xFF)]
    return ":".join(f"{octet:02x}" for octet in mac)


def change_mac(interface, new_mac):
    print(f"[+] Changing MAC address for {interface} to {new_mac}")
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])

def get_current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(['ifconfig', interface]).decode('utf-8')
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            print('[-] MAC address not found')
            return None
    except subprocess.CalledProcessError:
        print(f"[-] Could not read interface {interface}")
        return None

def main():
    options = get_arguments()

    print("Do you want to:")
    print("1. Generate a random MAC address")
    print("2. Enter your own MAC address")
    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        new_mac = generate_random_mac()
        print(f"[+] Generated Random MAC Address: {new_mac}")
    elif choice == "2":
        new_mac = input("Enter the new MAC address (format: xx:xx:xx:xx:xx:xx): ").strip()
        if not re.fullmatch(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", new_mac):
            print("[-] Invalid MAC address format. Exiting.")
            return
    else:
        print("[-] Invalid choice. Exiting.")
        return

    current_mac = get_current_mac(options.interface)
    print("Current MAC = " + str(current_mac))

    change_mac(options.interface, new_mac)

    current_mac = get_current_mac(options.interface)
    if current_mac == new_mac:
        print(f"[+] MAC address was successfully changed to {current_mac}")
    else:
        print("[-] MAC address did not get changed.")

if __name__ == "__main__":
    main()
