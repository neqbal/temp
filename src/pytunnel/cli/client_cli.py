#!/usr/bin/env python3
import argparse
from ..client.client import Client
from ..config import load_config

def main():
    """
    Entry point for the PyTunnel client.
    """
    parser = argparse.ArgumentParser(description="PyTunnel client.")
    parser.add_argument("--config", required=True, help="Path to the client configuration file.")
    args = parser.parse_args()

    config = load_config(args.config)
    server_addr = (config['server_addr'], config['server_port'])

    client = Client(config=config, server_addr=server_addr)
    client.run()

if __name__ == "__main__":
    main()
