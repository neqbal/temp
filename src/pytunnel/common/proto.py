"""
Protocol message definitions and pack/unpack functions.

PyTunnel uses a simple binary protocol with fixed-size headers.
"""
import struct
import logging

logger = logging.getLogger(__name__)

# Message types
MSG_INVALID = 0
MSG_INIT = 1
MSG_COOKIE_CHALLENGE = 2
MSG_INIT_WITH_COOKIE = 3
MSG_RESP = 4
MSG_DATA = 5

# Header formats
# 'B' is unsigned char (1 byte)
# 'I' is unsigned int (4 bytes)
# 'Q' is unsigned long long (8 bytes)
# '32s' is 32 bytes
HEADER_FMT = '!B'
MSG_INIT_FMT = '!B 32s'
MSG_COOKIE_CHALLENGE_FMT = '!B 16s I'
MSG_INIT_WITH_COOKIE_FMT = '!B 16s 32s'
MSG_RESP_FMT = '!B 32s'
MSG_DATA_FMT = '!B Q' # Plus encrypted data

# Sizes
MSG_INIT_LEN = struct.calcsize(MSG_INIT_FMT)
MSG_COOKIE_CHALLENGE_LEN = struct.calcsize(MSG_COOKIE_CHALLENGE_FMT)
MSG_INIT_WITH_COOKIE_LEN = struct.calcsize(MSG_INIT_WITH_COOKIE_FMT)
MSG_RESP_LEN = struct.calcsize(MSG_RESP_FMT)
MSG_DATA_HEADER_LEN = struct.calcsize(MSG_DATA_FMT)


def pack_msg_init(eph_pubkey):
    """Packs a MSG_INIT message."""
    return struct.pack(MSG_INIT_FMT, MSG_INIT, bytes(eph_pubkey))

def unpack_msg_init(payload):
    """Unpacks a MSG_INIT message."""
    _, eph_pubkey = struct.unpack(MSG_INIT_FMT, payload)
    return eph_pubkey

def pack_msg_cookie_challenge(cookie, timestamp):
    """Packs a MSG_COOKIE_CHALLENGE message."""
    return struct.pack(MSG_COOKIE_CHALLENGE_FMT, MSG_COOKIE_CHALLENGE, cookie, timestamp)

def unpack_msg_cookie_challenge(payload):
    """Unpacks a MSG_COOKIE_CHALLENGE message."""
    _, cookie, timestamp = struct.unpack(MSG_COOKIE_CHALLENGE_FMT, payload)
    return cookie, timestamp

def pack_msg_init_with_cookie(cookie, eph_pubkey):
    """Packs a MSG_INIT_WITH_COOKIE message."""
    return struct.pack(MSG_INIT_WITH_COOKIE_FMT, MSG_INIT_WITH_COOKIE, cookie, eph_pubkey)

def unpack_msg_init_with_cookie(payload):
    """Unpacks a MSG_INIT_WITH_COOKIE message."""
    _, cookie, eph_pubkey = struct.unpack(MSG_INIT_WITH_COOKIE_FMT, payload)
    return cookie, eph_pubkey

def pack_msg_resp(eph_pubkey):
    """Packs a MSG_RESP message."""
    return struct.pack(MSG_RESP_FMT, MSG_RESP, bytes(eph_pubkey))

def unpack_msg_resp(payload):
    """Unpacks a MSG_RESP message."""
    _, eph_pubkey = struct.unpack(MSG_RESP_FMT, payload)
    return eph_pubkey

def pack_msg_data(seq, ciphertext):
    """Packs a MSG_DATA message."""
    header = struct.pack(MSG_DATA_FMT, MSG_DATA, seq)
    return header + ciphertext

def unpack_msg_data(payload):
    """Unpacks a MSG_DATA message."""
    header = payload[:MSG_DATA_HEADER_LEN]
    ciphertext = payload[MSG_DATA_HEADER_LEN:]
    _, seq = struct.unpack(MSG_DATA_FMT, header)
    return seq, ciphertext

def get_msg_type(payload):
    """Gets the message type from a payload."""
    if not payload:
        return MSG_INVALID
    return struct.unpack(HEADER_FMT, payload[:1])[0]
