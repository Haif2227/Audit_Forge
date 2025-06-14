#!/usr/bin/env python
import scapy.all as scapy
import argparse
from scapy.layers import http
import signal
import sys
import os


captured_packets = []

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff")
    arguments = parser.parse_args()
    return arguments.interface

def spoof(iface):
    print(f"[*] Starting sniffing on interface: {iface}")
    try:
        scapy.sniff(iface=iface, store=False, prn=process_packet)
    except KeyboardInterrupt:
        handle_exit()

def process_packet(packet):
    
    captured_packets.append(packet)

    
    line = f"Packet: {packet.summary()}"
    
    # Add HTTP Request details if present
    if packet.haslayer(http.HTTPRequest):
        try:
            host = packet[http.HTTPRequest].Host.decode(errors="ignore")
            path = packet[http.HTTPRequest].Path.decode(errors="ignore")
            line += f" | HTTP: {host}{path}"
        except Exception:
            line += " | HTTP: [Error decoding host/path]"
    
    
    if packet.haslayer(scapy.Raw):
        try:
            raw_data = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
            line += f" | Raw: {raw_data[:50]}..."  # Truncate to 50 chars
        except Exception:
            line += " | Raw: [Error decoding raw data]"

    
    print(line)

def handle_exit():
    print("\n[!] Sniffing stopped. Saving captured packets to captures/sniffer.pcap...")
    save_to_pcap()
    sys.exit(0)

def save_to_pcap():
    folder = "captures"
    os.makedirs(folder, exist_ok=True)  
    filepath = os.path.join(folder, "sniffer.pcap")
    scapy.wrpcap(filepath, captured_packets)
    print(f"[+] Packets saved to {filepath}")


signal.signal(signal.SIGINT, lambda sig, frame: handle_exit())

iface = get_interface()
if iface:
    spoof(iface)
else:
    print("Please specify a valid interface using -i or --interface")
