#!/usr/bin/env python3
import argparse
import logging
from pytunnel.client.client import Client
from pytunnel.config import load_config
from pytunnel.logconfig import setup_logging

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="PyTunnel Client")
    parser.add_argument("--config", default="configs/client.yaml", help="Path to config file.")
    args = parser.parse_args()

    config = load_config(args.config)
    
    client = Client(config)
    try:
        client.run()
    except Exception as e:
        logging.error(f"Client crashed: {e}")

if __name__ == "__main__":
    main()
