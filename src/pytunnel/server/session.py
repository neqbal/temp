"""
Represents a client session on the server.

Each Session object stores the cryptographic keys, replay window, and
other state associated with a single connected client.
"""
import logging
from ..common.crypto import Encryptor, Decryptor
from ..common.replay import ReplayWindow

logger = logging.getLogger(__name__)

class Session:
    def __init__(self, client_addr, tx_key, rx_key):
        self.client_addr = client_addr
        self.encryptor = Encryptor(tx_key)
        self.decryptor = Decryptor(rx_key)
        self.replay_window = ReplayWindow()
        self.tx_seq = 0
        self.rx_seq = 0
        logger.info(f"Created new session for {client_addr}")

    def next_tx_seq(self):
        """Returns the next sequence number for an outgoing packet."""
        seq = self.tx_seq
        self.tx_seq += 1
        return seq
