"""
Represents a client session on the server.
"""
from ..common import crypto
from ..common.replay import ReplayWindow

class Session:
    def __init__(self, client_addr, tx_key, rx_key, tunnel_ip):
        self.client_addr = client_addr
        self.tx_key = tx_key
        self.rx_key = rx_key
        self.tunnel_ip = tunnel_ip
        self.encryptor = crypto.Encryptor(self.tx_key)
        self.decryptor = crypto.Decryptor(self.rx_key)
        self.replay_window = ReplayWindow()