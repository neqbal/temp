import pytest
from pytunnel.common import crypto
from nacl.public import PrivateKey

def test_key_derivation():
    """Tests that client and server derive the same symmetric keys."""
    client_static = PrivateKey.generate()
    server_static = PrivateKey.generate()
    client_eph = PrivateKey.generate()
    server_eph = PrivateKey.generate()

    # Client derives keys
    c_tx, c_rx = crypto.derive_keys(
        client_static, server_static.public_key, server_static.public_key,
        client_eph, server_eph.public_key, is_client=True
    )

    # Server derives keys
    s_rx, s_tx = crypto.derive_keys(
        server_static, client_static.public_key, client_static.public_key,
        server_eph, client_eph.public_key, is_client=False
    )

    assert c_tx == s_rx
    assert c_rx == s_tx
    assert c_tx != c_rx

def test_encryption():
    """Tests basic encryption and decryption."""
    key = b'thirty-two-byte-long-secret-key'
    encryptor = crypto.Encryptor(key)
    decryptor = crypto.Decryptor(key)
    
    message = b"This is a secret message."
    nonce = b'\x00' * 24
    
    ciphertext = encryptor.encrypt(message, nonce)
    plaintext = decryptor.decrypt(ciphertext, nonce)
    
    assert plaintext == message
