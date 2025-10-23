#!/usr/bin/env python3
import argparse
import logging
from ..client.client import Client
from ..config import load_config
from ..logconfig import setup_logging

def main():
    """
    Entry point for the PyTunnel client.
    """
    parser = argparse.ArgumentParser(description="PyTunnel client.")
    parser.add_argument("--config", required=True, help="Path to the client configuration file.")
    parser.add_argument("--disable-replay-protection", action="store_true", help="Disable replay attack protection.")
    parser.add_argument("--loglevel", default="INFO", help="Set the log level (e.g., DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--logfile", help="Path to a file to log to.")
    args = parser.parse_args()

    setup_logging(level=getattr(logging, args.loglevel.upper()), log_file=args.logfile)

    config = load_config(args.config)
    server_addr = (config['server_addr'], config['server_port'])

    client = Client(config=config, server_addr=server_addr, disable_replay_protection=args.disable_replay_protection)
    client.run()

if __name__ == "__main__":
    main()
