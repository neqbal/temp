"""
Configuration loading for PyTunnel.
"""
import yaml
from .common import log

def load_config(filepath):
    """Loads a YAML configuration file."""
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        log.log_error(f"Configuration file not found at '{filepath}'.")
        exit(1)
    except yaml.YAMLError as e:
        log.log_error(f"Error parsing YAML configuration file '{filepath}': {e}")
        exit(1)
