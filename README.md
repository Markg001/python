  **Python Projects Repository**
  
Welcome to my Python Projects repository! This repository serves as a learning space where I explore Python concepts and create practical tools for various purposes. Below is a summary of the files and scripts included in this repository, along with their functionality.
  **Repository Structure**
  
  **1. Arp_Poisoning.py**

**Description**: A script that demonstrates ARP (Address Resolution Protocol) poisoning, a network security concept.
**Purpose**: To understand and implement network manipulation techniques for educational purposes.
**Features**:
Intercepts communication between devices on a network.
Manipulates ARP tables to redirect packets.
Disclaimer: For educational use only. Misuse may violate laws and ethical guidelines.


  **2. Mac_Changer.py**
  
Description: A tool to modify the MAC (Media Access Control) address of network interfaces.
Purpose: Learn about network interfaces and enhance privacy by changing MAC addresses.
Features:
Lists current MAC addresses.
Randomly generates or sets a custom MAC address.
Restores the original MAC address.

**3. Network_Scanner.py**  

Description: A simple network scanner to identify active devices within a specified range.
Purpose: Understand how to interact with network protocols and gather basic device information.
Features:
Scans specified IP ranges.
Lists IP and MAC addresses of detected devices.

  **4. morse_decoder.py**
  
Description: A script to decode Morse code messages.
Purpose: Practice Python string manipulation and decoding algorithms.
Features:
Converts Morse code into plain text.
Supports custom message inputs.
Enhanced print formatting.

  **5. packet_sniffer.py**
  
Description: A packet sniffer to capture and analyze network traffic.
Purpose: Explore how to intercept and inspect data packets for educational purposes.
Features:
Captures raw packets from the network.
Displays source and destination details.
Disclaimer: For educational use only. Avoid unauthorized monitoring.

  **6. print.py**
  
Description: A utility script for testing and experimenting with Python's print() functionality.
Purpose: Explore Python's built-in functions and improve output formatting.
Features:
Demonstrates various print() techniques.
Serves as a learning aid for new Python learners.

  **DNS_SPOOFER.PY**

# DNS Spoofing Script

This Python script intercepts and modifies DNS requests to redirect traffic for a target domain to a specified IP address using Scapy and NetfilterQueue.

## Disclaimer

**Educational use only**. Unauthorized use of this script is illegal. Use it only in controlled environments where you have permission.

## Requirements

- Python 3
- Libraries: `scapy`, `netfilterqueue`
- Administrative privileges

## Installation & Setup

1. Install dependencies:
   ```bash
   pip install scapy NetfilterQueue
   ```
2. Configure IP tables (Linux):
   ```bash
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
   ```
3. Run the script:
   ```bash
   sudo python3 script_name.py
   ```

## Usage

1. Edit the `process_packet` function to specify the target domain and IP.
2. Start the script and route traffic through the host running it.

## Reset IP Tables

Stop the script with `Ctrl+C` and reset IP tables:
```bash
sudo iptables --flush
```


