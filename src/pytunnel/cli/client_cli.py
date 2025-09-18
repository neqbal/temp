#!/usr/bin/env python3
import argparse
from ..client.client import Client

def main():
    """
    Entry point for the PyTunnel client.
    """
    parser = argparse.ArgumentParser(description="PyTunnel client.")
    parser.add_argument("--server", required=True, help="Server address in the format ip:port.")
    args = parser.parse_args()

    ip, port_str = args.server.split(':')
    port = int(port_str)
    server_addr = (ip, port)

    # TODO: Set up logging
    # TODO: Load the configuration file
    client = Client(config=None, server_addr=server_addr)
    client.run()

if __name__ == "__main__":
    main()
