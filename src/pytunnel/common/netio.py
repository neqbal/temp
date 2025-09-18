"""
TUN/TAP device I/O and configuration helpers.

This module provides functions to create, configure, and read/write
from a TUN device, which is used to capture and inject IP packets.
"""
import os
import fcntl
import struct
import subprocess
import logging

logger = logging.getLogger(__name__)

# Linux-specific TUN/TAP constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def create_tun_device(name="tun0", ip_addr=None):
    """
    Creates and configures a TUN device.
    Returns a file descriptor for the device.
    """
    try:
        # Create the TUN device
        tun_fd = os.open('/dev/net/tun', os.O_RDWR)
        ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        logger.info(f"Successfully created TUN device '{name}'")

        # Configure the device with an IP address
        if ip_addr:
            subprocess.check_call(['sudo', 'ip', 'addr', 'add', ip_addr, 'dev', name])
            subprocess.check_call(['sudo', 'ip', 'link', 'set', 'dev', name, 'up'])
            logger.info(f"Configured {name} with IP {ip_addr} and brought it up.")

        return tun_fd
    except Exception as e:
        logger.error(f"Error creating or configuring TUN device: {e}")
        raise

def read_from_tun(fd):
    """Reads an IP packet from the TUN device."""
    return os.read(fd, 2048)

def write_to_tun(fd, packet):
    """Writes an IP packet to the TUN device."""
    os.write(fd, packet)
