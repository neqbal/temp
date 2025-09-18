"""
Logging configuration for PyTunnel.
"""
import logging

def setup_logging(level=logging.INFO):
    """Sets up basic logging."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
