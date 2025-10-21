"""
Cryptographic operations for PyTunnel.
"""

import base64
from nacl.public import PrivateKey, PublicKey, Box
from hkdf import Hkdf

def load_key(filepath):
    """Loads a base64-encoded key from a file."""
    with open(filepath, 'r') as f:
        return base64.b64decode(f.read())

def generate_ephemeral_keys():
    """Generates a new ephemeral X25519 key pair."""
    private_key = PrivateKey.generate()
    return private_key, private_key.public_key

def derive_keys(static_privkey, remote_static_pubkey, ephemeral_privkey, remote_ephemeral_pubkey, is_client):
    """
    Derives symmetric keys using a Noise-like protocol.
    """
    # Perform three X25519 DH exchanges
    if not isinstance(remote_static_pubkey, PublicKey):
        remote_static_pubkey = PublicKey(remote_static_pubkey)
    if not isinstance(remote_ephemeral_pubkey, PublicKey):
        remote_ephemeral_pubkey = PublicKey(remote_ephemeral_pubkey)

    dh1 = Box(static_privkey, remote_static_pubkey).shared_key()
    dh2 = Box(ephemeral_privkey, remote_ephemeral_pubkey).shared_key()
    #dh3 = Box(static_privkey, remote_ephemeral_pubkey).shared_key()

    # Concatenate DH results to form IKM
    ikm = dh1 + dh2 # + dh3

    # Use HKDF to derive tx and rx keys
    hkdf = Hkdf(b'', ikm) # No salt
    keys = hkdf.expand(b'', 64) # 64 bytes for two 32-byte keys

    tx_key = keys[:32]
    rx_key = keys[32:]

    if is_client:
        return tx_key, rx_key
    else:
        return rx_key, tx_key

from nacl.secret import SecretBox
import nacl.utils

class Encryptor:
    """Encrypts outgoing packets."""
    def __init__(self, key):
        self.box = SecretBox(key)

    def encrypt(self, plaintext):
        """Encrypts and authenticates plaintext. A random nonce is generated for each message."""
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        ciphertext = self.box.encrypt(plaintext, nonce)
        # The nonce is prepended to the ciphertext. The first 24 bytes are the nonce.
        return ciphertext

class Decryptor:
    """Decrypts incoming packets."""
    def __init__(self, key):
        self.box = SecretBox(key)

    def decrypt(self, ciphertext):
        """Decrypts and verifies ciphertext. The nonce is extracted from the first 24 bytes."""
        # The nonce is extracted from the beginning of the message
        nonce = ciphertext[:SecretBox.NONCE_SIZE]
        # The actual encrypted message is after the nonce
        message = ciphertext[SecretBox.NONCE_SIZE:]
        return self.box.decrypt(message, nonce)
