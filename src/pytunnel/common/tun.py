"""
TUN device creation and configuration for Linux.
"""
import os
import fcntl
import struct
import subprocess
from ..common import log

# Constants for TUN device creation on Linux, derived from <linux/if.h> and <linux/if_tun.h>
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000 # Don't provide packet information

def create_tun_interface(name="pytunnel0"):
    """
    Creates a persistent TUN interface.
    Returns the file descriptor for the TUN device.
    """
    tun_fd = -1
    try:
        # Open the TUN device file
        tun_fd = os.open("/dev/net/tun", os.O_RDWR)

        # Prepare the ioctl request structure (ifreq)
        # 16s for the interface name, H for the flags
        ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)

        # Call ioctl to create the interface with the specified name and flags
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        log.log_info(f"Successfully created TUN interface '{name}'.")
        return tun_fd
    except (IOError, OSError) as e:
        log.log_error(f"Error creating TUN interface: {e}")
        log.log_error("Please ensure you are running this with sufficient privileges (e.g., sudo) and that the 'tun' module is loaded ('sudo modprobe tun').")
        if tun_fd != -1:
            os.close(tun_fd)
        return None

def configure_tun_interface(name, ip_addr):
    """
    Configures the TUN interface with the given IP address.
    """
    log.log_info(f"Configuring TUN device {name} with IP {ip_addr}...")
    try:
        subprocess.run(["sudo", "ip", "addr", "add", ip_addr, "dev", name], check=True)
        subprocess.run(["sudo", "ip", "link", "set", name, "up"], check=True)
        log.log_info("TUN device configured successfully.")
    except subprocess.CalledProcessError as e:
        log.log_error(f"Failed to configure TUN device: {e}")
        log.log_error("Please ensure you are running with sudo privileges.")
        raise
