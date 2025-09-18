"""
The main PyTunnel client implementation.
"""
import socket
from ..common import crypto
from ..common import proto
from ..common import log
from nacl.public import PrivateKey, PublicKey

class Client:
    def __init__(self, config, server_addr):
        # TODO: Load configuration (server addr, port, keys)
        self.server_addr = server_addr
        self.config = config
        self.static_privkey = PrivateKey.generate() # TODO: Load from config
        self.static_pubkey = self.static_privkey.public_key
        self.server_static_pubkey = None # TODO: Load from config
        self.tx_key = None
        self.rx_key = None
        # TODO: Initialize ReplayWindow

    def run(self):
        """Starts the client and enters the main event loop."""
        log.log_info(f"Connecting to server at {self.server_addr[0]}:{self.server_addr[1]}")
        self.handshake()
        # TODO: Create TUN device
        # TODO: Create UDP socket
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
        log.log_sent("MSG_INIT")

        # Step 2: Receive MSG_COOKIE_CHALLENGE
        response, _ = sock.recvfrom(4096)
        cookie, timestamp = proto.unpack_msg_cookie_challenge(response)
        log.log_received("MSG_COOKIE_CHALLENGE")

        # Step 3: Send MSG_INIT_WITH_COOKIE
        msg = proto.pack_msg_init_with_cookie(cookie, timestamp, bytes(eph_pubkey), bytes(self.static_pubkey))
        sock.sendto(msg, self.server_addr)
        log.log_sent("MSG_INIT_WITH_COOKIE")

        # Step 4: Receive MSG_RESP
        response, _ = sock.recvfrom(4096)
        server_eph_pubkey = proto.unpack_msg_resp(response)
        log.log_received("MSG_RESP")

        # TODO: This is a placeholder for loading the server's static public key
        if self.server_static_pubkey is None:
            log.log_error("Server static public key not configured. Using a placeholder.")
            # This is insecure. In a real scenario, the server's public key would be known.
            # For the handshake to work, this key MUST match the public part of the
            # server's actual static private key.
            # We are generating a dummy one here, which will cause the handshake to fail
            # unless the server is also using a predictable key.
            dummy_server_privkey = PrivateKey(b'\x00'*32) # Placeholder
            self.server_static_pubkey = dummy_server_privkey.public_key


        self.tx_key, self.rx_key = crypto.derive_keys(
            self.static_privkey,
            self.server_static_pubkey,
            eph_privkey,
            server_eph_pubkey,
            is_client=True
        )

        log.log_info("Handshake successful. Session keys derived.")
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
