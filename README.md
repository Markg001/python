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

# HTTP Redirect Script

This Python script intercepts HTTP requests and redirects `.exe` file downloads to a specified URL using Scapy and NetfilterQueue.

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
   For testing locally:
   ```bash
   sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
   sudo iptables -I INPUT -j NFQUEUE --queue-num 0
   ```
3. Run the script:
   ```bash
   sudo python3 script_name.py
   ```

## Usage

- The script intercepts HTTP requests for `.exe` files and redirects them to `http://www.example.org/index.asp`.
- Modify the `set_load` function to change the redirection target.

## Reset IP Tables


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Packet Interception and Injection Script

This Python script uses `Scapy` and `NetfilterQueue` to intercept, modify, and forward packets in a queue. It demonstrates how to:

- Intercept HTTP requests and responses.
- Remove specific HTTP headers.
- Inject custom payloads into HTTP responses.

## Prerequisites

Ensure the following are installed on your system:

- **Python 3.x**
- **Scapy**: Install using `pip install scapy`
- **NetfilterQueue**: Install using `pip install NetfilterQueue`

You also need **root privileges** to run the script, as it interacts with system-level networking features.

## Features

1. **HTTP Request Modification**:
   - Removes the `Accept-Encoding` header from HTTP requests to prevent compression in responses.

2. **HTTP Response Injection**:
   - Injects a JavaScript alert (`<script>alert('YOU HAVE BEEN HACKED');</script>`) into HTTP responses containing `</body>` and `text/html`.
   - Adjusts the `Content-Length` header to account for the added content.

3. **Automatic Checksum Recalculation**:
   - Ensures the modified packets are valid by recalculating IP and TCP checksums.

## Usage

1. **Setup Packet Forwarding Rules**:
   Use `iptables` to redirect traffic to the NetfilterQueue:
   ```bash
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
   ```
   For local traffic, use:
   ```bash
   sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
   sudo iptables -I INPUT -j NFQUEUE --queue-num 0
   ```

2. **Run the Script**:
   ```bash
   sudo python3 script_name.py
   ```

3. **Cleanup After Execution**:
   Reset `iptables` rules with:
   ```bash
   sudo iptables --flush
   ```

## How It Works

1. **Packet Interception**:
   The script binds to a NetfilterQueue, which intercepts packets based on the `iptables` rules.

2. **Packet Processing**:
   - The script checks if a packet contains TCP and Raw data layers.
   - For HTTP requests (`dport == 80`): Removes the `Accept-Encoding` header.
   - For HTTP responses (`sport == 80`): Injects a JavaScript alert before the closing `</body>` tag if the content type is `text/html`.

3. **Packet Modification**:
   Modified packets have recalculated checksums and lengths before being forwarded.
Stop the script with `Ctrl+C` and reset IP tables:
```bash
sudo iptables --flush

# HTTP Packet Interceptor and Code Injector

This Python script demonstrates how to intercept and modify HTTP traffic. It uses `Scapy` and `NetfilterQueue` to manipulate packets, allowing users to inject custom content into HTTP responses. This tool is for educational and authorized testing purposes only.

## Features

- **HTTP Request Modification**:
  - Removes `Accept-Encoding` headers to bypass content compression.
  - Downgrades HTTP requests to HTTP/1.0 for simpler processing.

- **HTTP Response Injection**:
  - Identifies `text/html` content and injects a custom JavaScript alert before the `</body>` tag.
  - Updates the `Content-Length` header dynamically to ensure proper content delivery.

- **Dynamic Packet Handling**:
  - Recalculates IP and TCP checksums and updates headers for modified packets.

## Usage

1. **Set Up Packet Redirection**:
   - Configure `iptables` to forward packets to a NetfilterQueue:
     ```bash
     sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
     ```

2. **Run the Script**:
   - Execute the script with administrative privileges:
     ```bash
     sudo python3 script_name.py
     ```
