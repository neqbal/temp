#!/usr/bin/env python3
import argparse
from ..server.server import Server

def main():
    """
    Entry point for the PyTunnel server.
    """
    parser = argparse.ArgumentParser(description="PyTunnel server.")
    parser.add_argument("--vulnerable", action="store_true", help="Run in a vulnerable mode without DDoS protection (for testing).")
    args = parser.parse_args()

    # TODO: Set up logging
    # TODO: Load the configuration file
    server = Server(config=None, vulnerable=args.vulnerable)
    server.run()

if __name__ == "__main__":
    main()
