#!/usr/bin/env python3
import argparse
from scapy.all import *

def main():
    parser = argparse.ArgumentParser(description="PyTunnel replay attack tool.")
    parser.add_argument("--pcap", required=True, help="PCAP file with captured packets.")
    parser.add_argument("--send-to", required=True, help="Target to send to (e.g., 1.2.3.4:51820).")
    args = parser.parse_args()

    target_ip, target_port = args.send_to.split(':')
    target_port = int(target_port)

    packets = rdpcap(args.pcap)
    
    # Find the first PyTunnel data packet in the capture
    data_packet = None
    for p in packets:
        if p.haslayer(UDP) and p[UDP].dport == target_port:
            # This is a simplistic check. A real tool would be more robust.
            # We assume the first UDP packet to the target port is what we want to replay.
            data_packet = p
            break
            
    if not data_packet:
        print("No suitable packet found in PCAP file.")
        return

    print("Replaying packet...")
    
    # Modify the destination to ensure it goes to the right place
    data_packet[IP].dst = target_ip
    data_packet[UDP].dport = target_port
    
    # Remove checksums so Scapy recalculates them
    del data_packet[IP].chksum
    del data_packet[UDP].chksum
    
    send(data_packet, verbose=True)
    print("Packet sent. The server should drop it if replay protection is working.")

if __name__ == "__main__":
    main()
