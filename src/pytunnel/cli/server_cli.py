#!/usr/bin/env python3
import argparse
import logging
from pytunnel.server.server import Server
from pytunnel.config import load_config
from pytunnel.logconfig import setup_logging

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="PyTunnel Server")
    parser.add_argument("--config", default="configs/server.yaml", help="Path to config file.")
    args = parser.parse_args()

    config = load_config(args.config)
    
    server = Server(config)
    try:
        server.run()
    except Exception as e:
        logging.error(f"Server crashed: {e}")

if __name__ == "__main__":
    main()
