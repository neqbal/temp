import socket
import os
import struct
import select
from ..common import proto
from ..common.cookie import CookieManager
from ..common import crypto
from ..common import log
from ..common import tun
from .session import Session
from nacl.public import PrivateKey

class Server:
    def __init__(self, config, vulnerable=False):
        self.vulnerable = vulnerable
        # TODO: Load configuration (listen addr, port, keys)
        self.listen_addr = ('0.0.0.0', 51820) # TODO: Load from config
        self.config = config
        self.cookie_manager = CookieManager(os.urandom(32)) # TODO: Use a persistent secret
        self.sessions = {}
        self.tun_fd = -1

        try:
            self.static_privkey = PrivateKey(crypto.load_key('configs/server.key'))
            log.log_info("Server static key loaded successfully.")
        except FileNotFoundError:
            log.log_error("Server key file not found!")
            log.log_error("Please run 'python3 scripts/genkeys.py --out-dir configs --name server' to generate keys.")
            exit(1)

    def run(self):
        """Starts the server and enters the main event loop.""" 
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self.listen_addr)
        log.log_info(f"Server listening on {self.listen_addr[0]}:{self.listen_addr[1]}")

        if self.vulnerable:
            log.log_error("Server is running in VULNERABLE mode. DDoS protection is OFF.")

        # Setup TUN device
        self.tun_fd = tun.create_tun_interface()
        if self.tun_fd < 0:
            log.log_error("Failed to create TUN interface. Exiting.")
            sock.close()
            return

        # TODO: Get interface name and IP from config
        tun_name = "pytunnel0"
        tun_ip = "10.0.0.1/24"

        log.log_info(f"Configuring TUN device {tun_name}...")
        try:
            tun.configure_tun_interface(tun_name, tun_ip)
        except Exception as e:
            log.log_error(f"Failed to configure TUN device: {e}")
            return

        log.log_info("Entering main loop. Forwarding traffic...")
        try:
            while True:
                readable, _, _ = select.select([sock, self.tun_fd], [], [])
                for r in readable:
                    if r is sock:
                        payload, client_addr = sock.recvfrom(4096)
                        self.handle_udp_packet(payload, client_addr, sock)
                    if r is self.tun_fd:
                        self.handle_tun_packet(sock)
        except KeyboardInterrupt:
            log.log_info("Server shutting down.")
        finally:
            if self.tun_fd >= 0:
                os.close(self.tun_fd)
            sock.close()

    def handle_udp_packet(self, payload, client_addr, sock):
        """Handles a packet received from the UDP socket."""
        try:
            msg_type = proto.get_msg_type(payload)
            if msg_type == proto.MSG_TYPE_INIT:
                self.handle_msg_init(payload, client_addr, sock)
            elif msg_type == proto.MSG_TYPE_INIT_WITH_COOKIE:
                if not self.vulnerable:
                    self.handle_msg_init_with_cookie(payload, client_addr, sock)
            elif msg_type == proto.MSG_TYPE_DATA:
                self.handle_msg_data(payload, client_addr)

        except (struct.error, IndexError):
            log.log_error(f"Received malformed packet from {client_addr}")

    def handle_tun_packet(self, sock):
        """Handles a packet received from the TUN device."""
        try:
            plaintext = os.read(self.tun_fd, 4096)
            log.log_info(f"Read {len(plaintext)} bytes from TUN device.")

            # --- ROUTING LOGIC --- #
            # This is a major simplification. A real VPN would inspect the
            # destination IP of the packet and look up the correct client session.
            # For now, we just broadcast the packet to all connected clients.
            if not self.sessions:
                log.log_info("No clients connected, dropping packet.")
                return

            log.log_info(f"Broadcasting TUN packet to {len(self.sessions)} client(s).")
            for client_addr, session in self.sessions.items():
                encrypted_payload = session.encryptor.encrypt(plaintext)
                msg = proto.pack_msg_data(encrypted_payload)
                sock.sendto(msg, client_addr)
                log.log_sent(f"MSG_DATA to {client_addr}")

        except Exception as e:
            log.log_error(f"Error handling TUN packet: {e}")

    def handle_msg_init(self, payload, client_addr, sock):
        """Handles an initial handshake message."""
        log.log_received(f"MSG_INIT from {client_addr[0]}:{client_addr[1]}")
        try:
            _, client_static_pubkey = proto.unpack_msg_init(payload)

            if self.vulnerable:
                # In vulnerable mode, we skip the cookie and proceed to an expensive (but useless) key derivation
                log.log_error("VULNERABLE MODE: Performing expensive key derivation immediately!")
                server_eph_privkey, _ = crypto.generate_ephemeral_keys()
                crypto.derive_keys(self.static_privkey, client_static_pubkey, server_eph_privkey, b'\x00'*32, is_client=False)
            else:
                cookie, timestamp = self.cookie_manager.generate_cookie(client_addr)
                response = proto.pack_msg_cookie_challenge(cookie, timestamp)
                sock.sendto(response, client_addr)
                log.log_sent(f"MSG_COOKIE_CHALLENGE to {client_addr[0]}:{client_addr[1]}")

        except (struct.error, IndexError):
            log.log_error(f"Received malformed MSG_INIT from {client_addr}")

    def handle_msg_init_with_cookie(self, payload, client_addr, sock):
        """Handles a handshake message that includes a cookie."""
        log.log_received(f"MSG_INIT_WITH_COOKIE from {client_addr[0]}:{client_addr[1]}")
        try:
            cookie, timestamp, client_eph_pubkey, client_static_pubkey = proto.unpack_msg_init_with_cookie(payload)
            if not self.cookie_manager.verify_cookie(cookie, timestamp, client_addr):
                log.log_error(f"Invalid cookie from {client_addr}")
                return

            # TODO: Verify client_static_pubkey against an allowlist

            log.log_info("Cookie verified successfully")
            server_eph_privkey, server_eph_pubkey = crypto.generate_ephemeral_keys()

            tx_key, rx_key = crypto.derive_keys(
                self.static_privkey,
                client_static_pubkey,
                server_eph_privkey,
                client_eph_pubkey,
                is_client=False
            )

            log.log_info(f"Server TX key: {tx_key.hex()}")
            log.log_info(f"Server RX key: {rx_key.hex()}")

            session = Session(client_addr, tx_key, rx_key)
            self.sessions[client_addr] = session
            log.log_info(f"Session created for {client_addr[0]}:{client_addr[1]}")

            response = proto.pack_msg_resp(bytes(server_eph_pubkey))
            sock.sendto(response, client_addr)
            log.log_sent(f"MSG_RESP to {client_addr[0]}:{client_addr[1]}")

        except (struct.error, IndexError):
            log.log_error(f"Received malformed MSG_INIT_WITH_COOKIE from {client_addr}")

    def handle_msg_data(self, payload, client_addr):
        """Handles an encrypted data message."""
        log.log_received(f"MSG_DATA from {client_addr}")
        session = self.sessions.get(client_addr)
        if not session:
            log.log_error(f"Received MSG_DATA from unknown client {client_addr}. Ignoring.")
            return

        try:
            encrypted_payload = proto.unpack_msg_data(payload)
            # TODO: Check for replays
            plaintext = session.decryptor.decrypt(encrypted_payload)
            os.write(self.tun_fd, plaintext)
            log.log_info(f"Wrote {len(plaintext)} bytes to TUN device.")
        except Exception as e:
            log.log_error(f"Failed to decrypt/write packet from {client_addr}: {e}")
