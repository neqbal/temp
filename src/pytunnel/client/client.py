"""
The main PyTunnel client implementation.
"""

class Client:
    def __init__(self, config):
        # TODO: Load configuration (server addr, port, keys)
        # TODO: Initialize ReplayWindow
        pass

    def run(self):
        """Starts the client and enters the main event loop."""
        # TODO: Create TUN device
        # TODO: Create UDP socket
        # TODO: Call self.handshake()
        # TODO: Use select.select to wait for I/O on socket and TUN fd
        # TODO: In the loop, call the appropriate handler
        pass

    def handshake(self):
        """Performs the handshake with the server."""
        # TODO: Step 1: Send MSG_INIT
        # TODO: Step 2: Receive MSG_COOKIE_CHALLENGE
        # TODO: Step 3: Send MSG_INIT_WITH_COOKIE
        # TODO: Step 4: Receive MSG_RESP
        # TODO: Derive keys and create Encryptor/Decryptor
        pass

    def handle_udp_packet(self):
        """Handles a packet received from the UDP socket."""
        # TODO: Receive packet
        # TODO: Unpack MSG_DATA
        # TODO: Check for replays
        # TODO: If not a replay, decrypt
        # TODO: Write plaintext to TUN device
        pass

    def handle_tun_packet(self):
        """Handles a packet received from the TUN device."""
        # TODO: Read packet from TUN
        # TODO: Encrypt the packet
        # TODO: Pack into a MSG_DATA
        # TODO: Send over the UDP socket
        pass
