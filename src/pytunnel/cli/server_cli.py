#!/usr/bin/env python3
import argparse
import logging
from ..server.server import Server
from ..config import load_config
from ..logconfig import setup_logging

def main():
    """
    Entry point for the PyTunnel server.
    """
    parser = argparse.ArgumentParser(description="PyTunnel server.")
    parser.add_argument("--config", required=True, help="Path to the server configuration file.")
    parser.add_argument("--vulnerable", action="store_true", help="Run in a vulnerable mode without DDoS protection (for testing).")
    parser.add_argument("--disable-replay-protection", action="store_true", help="Disable replay attack protection.")
    parser.add_argument("--loglevel", default="INFO", help="Set the log level (e.g., DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--logfile", help="Path to a file to log to.")
    args = parser.parse_args()

    setup_logging(level=getattr(logging, args.loglevel.upper()), log_file=args.logfile)

    config = load_config(args.config)
    server = Server(config=config, vulnerable=args.vulnerable, disable_replay_protection=args.disable_replay_protection)
    server.run()

if __name__ == "__main__":
    main()
