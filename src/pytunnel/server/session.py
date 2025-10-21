"""
Represents a client session on the server.
"""
from ..common import crypto

class Session:
    def __init__(self, client_addr, tx_key, rx_key):
        self.client_addr = client_addr
        self.tx_key = tx_key
        self.rx_key = rx_key
        self.encryptor = crypto.Encryptor(self.tx_key)
        self.decryptor = crypto.Decryptor(self.rx_key)
        # TODO: Initialize replay window