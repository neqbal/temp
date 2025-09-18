"""
Protocol message definitions and pack/unpack functions.
"""
import struct

# TODO: Define message types and header formats
# MSG_INIT = 1
# ...

def pack_msg_init(eph_pubkey):
    """Packs a MSG_INIT message."""
    # TODO: Implement packing
    pass

def unpack_msg_init(payload):
    """Unpacks a MSG_INIT message."""
    # TODO: Implement unpacking
    pass

# TODO: Add pack/unpack functions for all other message types:
# - MSG_COOKIE_CHALLENGE
# - MSG_INIT_WITH_COOKIE
# - MSG_RESP
# - MSG_DATA

def get_msg_type(payload):
    """Gets the message type from a payload."""
    # TODO: Implement message type extraction
    pass
