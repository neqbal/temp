#!/usr/bin/env python3
"""
Captures and replays a MSG_DATA packet to test replay protection.
"""

import argparse
import sys
import os

# Add src directory to path to allow importing pytunnel modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from scapy.all import sniff, send, IP, UDP
from pytunnel.common import proto

class ReplayAttacker:
    def __init__(self, target_ip, target_port):
        self.target_ip = target_ip
        self.target_port = target_port
        self.captured_packet = None

    def packet_callback(self, packet):
        """Callback function for Scapy's sniff()."""
        if UDP in packet and packet[UDP].dport == self.target_port:
            payload = bytes(packet[UDP].payload)
            msg_type = proto.get_msg_type(payload)

            if msg_type == proto.MSG_TYPE_DATA:
                print("\n[+] Captured a MSG_DATA packet!")
                self.captured_packet = payload
                return True # Stop sniffing
        return False

    def run(self):
        """
        Sniffs for a data packet, then replays it.
        """
        print(f"[*] Sniffing for a data packet destined for port {self.target_port}...")
        print("[*] Please generate some traffic through the tunnel (e.g., ping the other side).")
        
        sniff(prn=self.packet_callback, filter=f"udp and port {self.target_port}", store=0, stop_filter=lambda p: self.captured_packet is not None)

        if self.captured_packet:
            print("[*] Captured packet. Now replaying it.")
            
            # The source IP and port don't matter for this attack
            replay_packet = IP(dst=self.target_ip) / UDP(dport=self.target_port, sport=12345) / self.captured_packet
            
            # Send the packet for the first time (this one should be accepted)
            send(replay_packet, verbose=0)
            print("[+] Sent original packet.")

            # Send the exact same packet again (this one should be rejected)
            send(replay_packet, verbose=0)
            print("[+] Sent replayed packet.")
            print("\n[*] Attack finished. Check the server/client logs for a 'Replay detected!' message.")
        else:
            print("\n[-] No suitable data packet was captured. Please try again.")

def main():
    """
    Parses arguments and runs the replay attack.
    """
    if os.geteuid() != 0:
        sys.stderr.write("This script must be run as root to sniff packets.\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Run a replay attack simulation on the PyTunnel server or client.")
    parser.add_argument("--target", required=True, help="The target IP address (server or client)." )
    parser.add_argument("--port", required=True, type=int, help="The target's UDP port.")
    args = parser.parse_args()

    attacker = ReplayAttacker(args.target, args.port)
    attacker.run()

if __name__ == "__main__":
    main()
