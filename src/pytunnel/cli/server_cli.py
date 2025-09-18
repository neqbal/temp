#!/usr/bin/env python3
import argparse
from ..server.server import Server

def main():
    """
    Entry point for the PyTunnel server.
    """
    # TODO: Set up logging
    # TODO: Parse command-line arguments (--config)
    # TODO: Load the configuration file
    server = Server(config=None)
    server.run()

if __name__ == "__main__":
    main()
