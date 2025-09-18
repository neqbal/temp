import pytest
from pytunnel.common import proto
from nacl.public import PublicKey

def test_msg_init_packing():
    eph_pubkey = b'\x01' * 32
    packed = proto.pack_msg_init(eph_pubkey)
    unpacked_key = proto.unpack_msg_init(packed)
    assert unpacked_key == eph_pubkey
    assert proto.get_msg_type(packed) == proto.MSG_INIT

def test_msg_data_packing():
    seq = 12345
    ciphertext = b"encrypted data"
    packed = proto.pack_msg_data(seq, ciphertext)
    unpacked_seq, unpacked_ciphertext = proto.unpack_msg_data(packed)
    assert unpacked_seq == seq
    assert unpacked_ciphertext == ciphertext
    assert proto.get_msg_type(packed) == proto.MSG_DATA
