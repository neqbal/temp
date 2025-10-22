#!/usr/bin/env python3
import argparse
from ..server.server import Server
from ..config import load_config

def main():
    """
    Entry point for the PyTunnel server.
    """
    parser = argparse.ArgumentParser(description="PyTunnel server.")
    parser.add_argument("--config", required=True, help="Path to the server configuration file.")
    parser.add_argument("--vulnerable", action="store_true", help="Run in a vulnerable mode without DDoS protection (for testing).")
    args = parser.parse_args()

    config = load_config(args.config)
    server = Server(config=config, vulnerable=args.vulnerable)
    server.run()

if __name__ == "__main__":
    main()
