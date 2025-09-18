"""
Represents a client session on the server.
"""

class Session:
    def __init__(self, client_addr, tx_key, rx_key):
        # TODO: Store client_addr
        # TODO: Create Encryptor and Decryptor instances
        # TODO: Create a ReplayWindow instance
        # TODO: Initialize sequence numbers
        pass

    def next_tx_seq(self):
        """Returns the next sequence number for an outgoing packet."""
        # TODO: Increment and return the sequence number
        pass
