"""
Protocol message definitions and pack/unpack functions.
"""
import struct

MSG_TYPE_INIT = 1
MSG_TYPE_COOKIE_CHALLENGE = 2
MSG_TYPE_INIT_WITH_COOKIE = 3
MSG_TYPE_RESP = 4
MSG_TYPE_DATA = 5

# Header: message type (1 byte)
MSG_HEADER_FORMAT = '!B'
MSG_HEADER_SIZE = struct.calcsize(MSG_HEADER_FORMAT)

# MSG_INIT: header || ephemeral_pubkey (32 bytes) || static_pubkey (32 bytes)
MSG_INIT_FORMAT = '!B32s32s'
MSG_INIT_SIZE = struct.calcsize(MSG_INIT_FORMAT)

def pack_msg_init(eph_pubkey, static_pubkey):
    """Packs a MSG_INIT message."""
    return struct.pack(MSG_INIT_FORMAT, MSG_TYPE_INIT, eph_pubkey, static_pubkey)

def unpack_msg_init(payload):
    """Unpacks a MSG_INIT message."""
    _, eph_pubkey, static_pubkey = struct.unpack(MSG_INIT_FORMAT, payload)
    return eph_pubkey, static_pubkey

# TODO: Add pack/unpack functions for all other message types:
# - MSG_COOKIE_CHALLENGE
# - MSG_INIT_WITH_COOKIE
# - MSG_RESP
# - MSG_DATA

# MSG_COOKIE_CHALLENGE: header || cookie (32 bytes) || timestamp (4 bytes)
MSG_COOKIE_CHALLENGE_FORMAT = '!B32sI'
MSG_COOKIE_CHALLENGE_SIZE = struct.calcsize(MSG_COOKIE_CHALLENGE_FORMAT)

def pack_msg_cookie_challenge(cookie, timestamp):
    """Packs a MSG_COOKIE_CHALLENGE message."""
    return struct.pack(MSG_COOKIE_CHALLENGE_FORMAT, MSG_TYPE_COOKIE_CHALLENGE, cookie, timestamp)

def unpack_msg_cookie_challenge(payload):
    """Unpacks a MSG_COOKIE_CHALLENGE message."""
    _, cookie, timestamp = struct.unpack(MSG_COOKIE_CHALLENGE_FORMAT, payload)
    return cookie, timestamp

# MSG_INIT_WITH_COOKIE: header || cookie (32 bytes) || timestamp (4 bytes) || eph_pubkey (32 bytes) || static_pubkey (32 bytes)
MSG_INIT_WITH_COOKIE_FORMAT = '!B32sI32s32s'
MSG_INIT_WITH_COOKIE_SIZE = struct.calcsize(MSG_INIT_WITH_COOKIE_FORMAT)

def pack_msg_init_with_cookie(cookie, timestamp, eph_pubkey, static_pubkey):
    """Packs a MSG_INIT_WITH_COOKIE message."""
    return struct.pack(MSG_INIT_WITH_COOKIE_FORMAT, MSG_TYPE_INIT_WITH_COOKIE, cookie, timestamp, eph_pubkey, static_pubkey)

def unpack_msg_init_with_cookie(payload):
    """Unpacks a MSG_INIT_WITH_COOKIE message."""
    _, cookie, timestamp, eph_pubkey, static_pubkey = struct.unpack(MSG_INIT_WITH_COOKIE_FORMAT, payload)
    return cookie, timestamp, eph_pubkey, static_pubkey

# MSG_RESP: header || ephemeral_pubkey (32 bytes)
MSG_RESP_FORMAT = '!B32s'
MSG_RESP_SIZE = struct.calcsize(MSG_RESP_FORMAT)

def pack_msg_resp(eph_pubkey):
    """Packs a MSG_RESP message."""
    return struct.pack(MSG_RESP_FORMAT, MSG_TYPE_RESP, eph_pubkey)

def unpack_msg_resp(payload):
    """Unpacks a MSG_RESP message."""
    _, eph_pubkey = struct.unpack(MSG_RESP_FORMAT, payload)
    return eph_pubkey

def get_msg_type(payload):
    """Gets the message type from a payload."""
    msg_type, = struct.unpack(MSG_HEADER_FORMAT, payload[:MSG_HEADER_SIZE])
    return msg_type
