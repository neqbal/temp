"""
Cryptographic operations for PyTunnel.

This module wraps PyNaCl for X25519 Diffie-Hellman, HKDF, and
ChaCha20-Poly1305 AEAD encryption.
"""
import base64
import logging
from nacl.public import PrivateKey, PublicKey
from nacl.bindings import crypto_kx_server_session_keys, crypto_kx_client_session_keys
from nacl.secret import SecretBox
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

# Constants
KEY_SIZE = 32

def load_key(filepath):
    """Loads a base64-encoded key from a file."""
    with open(filepath, 'r') as f:
        return base64.b64decode(f.read().strip())

def generate_ephemeral_keys():
    """Generates a new ephemeral X25519 key pair."""
    return PrivateKey.generate()

def derive_keys(static_privkey, static_pubkey, remote_static_pubkey,
                ephemeral_privkey, remote_ephemeral_pubkey, is_client):
    """
    Derives symmetric keys using a Noise-like protocol with X25519.
    This is a simplified version of the Noise 'IK' pattern.
    """
    # TODO: This is a simplified key derivation. A real implementation
    # should follow a standard Noise protocol more closely.

    # DH between static keys
    dh1 = static_privkey.exchange(remote_static_pubkey)
    # DH between ephemeral and remote static
    dh2 = ephemeral_privkey.exchange(remote_static_pubkey)
    # DH between static and remote ephemeral
    dh3 = static_privkey.exchange(remote_ephemeral_pubkey)

    ikm = dh1 + dh2 + dh3
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_SIZE,
        salt=b'',
        info=b'pytunnel-key-derivation',
    )
    okm = hkdf.derive(ikm)

    if is_client:
        tx_key = okm[:KEY_SIZE]
        rx_key = okm[KEY_SIZE:]
    else: # Server
        rx_key = okm[:KEY_SIZE]
        tx_key = okm[KEY_SIZE:]
        
    logger.info("Derived new session keys.")
    return tx_key, rx_key


class Encryptor:
    """Encrypts outgoing packets."""
    def __init__(self, key):
        self.box = SecretBox(key)

    def encrypt(self, plaintext, nonce):
        return self.box.encrypt(plaintext, nonce)

class Decryptor:
    """Decrypts incoming packets."""
    def __init__(self, key):
        self.box = SecretBox(key)

    def decrypt(self, ciphertext, nonce):
        return self.box.decrypt(ciphertext, nonce)
