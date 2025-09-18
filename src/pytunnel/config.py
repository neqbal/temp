"""
Configuration loading for PyTunnel.
"""
import yaml
import logging

logger = logging.getLogger(__name__)

def load_config(filepath):
    """Loads a YAML configuration file."""
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration file {filepath}: {e}")
        raise
