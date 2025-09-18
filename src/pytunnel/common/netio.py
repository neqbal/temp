"""
TUN/TAP device I/O and configuration helpers.
"""

def create_tun_device(name="tun0", ip_addr=None):
    """
    Creates and configures a TUN device.
    """
    # TODO: Open /dev/net/tun
    # TODO: Use ioctl with TUNSETIFF to create the interface
    # TODO: Use subprocess to run `ip addr` and `ip link` commands to configure it
    # TODO: Return the file descriptor
    pass

def read_from_tun(fd):
    """Reads an IP packet from the TUN device."""
    # TODO: Implement os.read
    pass

def write_to_tun(fd, packet):
    """Writes an IP packet to the TUN device."""
    # TODO: Implement os.write
    pass
