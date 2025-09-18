"""
The main PyTunnel client implementation.
"""
import socket
from ..common import crypto
from ..common import proto
from nacl.public import PrivateKey

class Client:
    def __init__(self, config):
        # TODO: Load configuration (server addr, port, keys)
        self.server_addr = ('127.0.0.1', 51820) # TODO: Load from config
        self.config = config
        self.static_privkey = PrivateKey.generate() # TODO: Load from config
        self.static_pubkey = self.static_privkey.public_key
        # TODO: Initialize ReplayWindow

    def run(self):
        """Starts the client and enters the main event loop."""
        # TODO: Create TUN device
        # TODO: Create UDP socket
        self.handshake()
        # TODO: Use select.select to wait for I/O on socket and TUN fd
        # TODO: In the loop, call the appropriate handler
        pass

    def handshake(self):
        """Performs the handshake with the server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Step 1: Send MSG_INIT
        eph_privkey, eph_pubkey = crypto.generate_ephemeral_keys()
        msg = proto.pack_msg_init(bytes(eph_pubkey), bytes(self.static_pubkey))
        sock.sendto(msg, self.server_addr)

        print("Sent MSG_INIT to server")

        # Step 2: Receive MSG_COOKIE_CHALLENGE
        response, _ = sock.recvfrom(4096)
        cookie, timestamp = proto.unpack_msg_cookie_challenge(response)
        print("Received MSG_COOKIE_CHALLENGE from server")

        # Step 3: Send MSG_INIT_WITH_COOKIE
        msg = proto.pack_msg_init_with_cookie(cookie, timestamp, bytes(eph_pubkey), bytes(self.static_pubkey))
        sock.sendto(msg, self.server_addr)
        print("Sent MSG_INIT_WITH_COOKIE to server")

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
