import socket
import os
import struct
from ..common import proto
from ..common.cookie import CookieManager
from ..common import crypto
from .session import Session
from nacl.public import PrivateKey

class Server:
    def __init__(self, config):
        # TODO: Load configuration (listen addr, port, keys)
        self.listen_addr = ('0.0.0.0', 51820) # TODO: Load from config
        self.config = config
        self.cookie_manager = CookieManager(os.urandom(32)) # TODO: Use a persistent secret
        self.sessions = {}
        self.static_privkey = PrivateKey.generate() # TODO: Load from config

    def run(self):
        """Starts the server and enters the main event loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self.listen_addr)
        print(f"Server listening on {self.listen_addr}")

        while True:
            payload, client_addr = sock.recvfrom(4096)
            self.handle_udp_packet(payload, client_addr, sock)

    def handle_udp_packet(self, payload, client_addr, sock):
        """Handles a packet received from the UDP socket."""
        try:
            msg_type = proto.get_msg_type(payload)
            if msg_type == proto.MSG_TYPE_INIT:
                self.handle_msg_init(payload, client_addr, sock)
            elif msg_type == proto.MSG_TYPE_INIT_WITH_COOKIE:
                self.handle_msg_init_with_cookie(payload, client_addr, sock)
            # TODO: Add other message handlers
        except (struct.error, IndexError):
            print(f"Received malformed packet from {client_addr}")


    def handle_tun_packet(self):
        """Handles a packet received from the TUN device."""
        # TODO: Read packet from TUN
        # TODO: Find the correct client session
        # TODO: Encrypt the packet
        # TODO: Pack it into a MSG_DATA
        # TODO: Send it over the UDP socket
        pass

    def handle_msg_init(self, payload, client_addr, sock):
        """Handles an initial handshake message."""
        print(f"Received MSG_INIT from {client_addr}")
        try:
            eph_pubkey, static_pubkey = proto.unpack_msg_init(payload)
            cookie, timestamp = self.cookie_manager.generate_cookie(client_addr)
            response = proto.pack_msg_cookie_challenge(cookie, timestamp)
            sock.sendto(response, client_addr)
            print(f"Sent MSG_COOKIE_CHALLENGE to {client_addr}")
        except struct.error:
            print(f"Received malformed MSG_INIT from {client_addr}")


    def handle_msg_init_with_cookie(self, payload, client_addr, sock):
        """Handles a handshake message that includes a cookie."""
        print(f"Received MSG_INIT_WITH_COOKIE from {client_addr}")
        try:
            cookie, timestamp, client_eph_pubkey, client_static_pubkey = proto.unpack_msg_init_with_cookie(payload)
            if not self.cookie_manager.verify_cookie(cookie, timestamp, client_addr):
                print(f"Invalid cookie from {client_addr}")
                return

            # Cookie is valid, proceed with handshake
            server_eph_privkey, server_eph_pubkey = crypto.generate_ephemeral_keys()

            tx_key, rx_key = crypto.derive_keys(
                self.static_privkey,
                client_static_pubkey,
                server_eph_privkey,
                client_eph_pubkey,
                is_client=False
            )

            session = Session(client_addr, tx_key, rx_key)
            self.sessions[client_addr] = session
            print(f"Session created for {client_addr}")

            response = proto.pack_msg_resp(bytes(server_eph_pubkey))
            sock.sendto(response, client_addr)
            print(f"Sent MSG_RESP to {client_addr}")

        except (struct.error, IndexError):
            print(f"Received malformed MSG_INIT_WITH_COOKIE from {client_addr}")


    def handle_msg_data(self, payload, client_addr):
        """Handles an encrypted data message."""
        # TODO: Find the client's session
        # TODO: Unpack the MSG_DATA
        # TODO: Check for replays
        # TODO: If not a replay, decrypt the packet
        # TODO: Write the plaintext packet to the TUN device
        pass
