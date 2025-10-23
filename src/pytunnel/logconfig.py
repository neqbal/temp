"""
Logging configuration for PyTunnel.
"""
import logging
import sys

def setup_logging(level=logging.INFO, log_file=None):
    """Sets up basic logging."""
    root = logging.getLogger()
    root.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # File handler
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh.setFormatter(formatter)
        root.addHandler(fh)
