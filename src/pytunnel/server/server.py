"""
The main PyTunnel server implementation.

The server listens for UDP packets, handles the handshake process,
manages client sessions, and forwards packets between the TUN
device and the UDP socket.
"""
import socket
import logging
import select
from nacl.public import PrivateKey, PublicKey

from ..common import proto, crypto, netio
from ..common.cookie import CookieManager
from .session import Session

logger = logging.getLogger(__name__)

class Server:
    def __init__(self, config):
        self.config = config
        self.listen_addr = config['listen_addr']
        self.listen_port = config['listen_port']
        self.static_privkey = PrivateKey(crypto.load_key(config['private_key_file']))
        self.client_static_pubkey = PublicKey(crypto.load_key(config['client_public_key_file']))
        self.cookie_manager = CookieManager()
        self.sessions = {}  # Maps client_addr to Session object
        self.tun_fd = None
        self.sock = None

    def run(self):
        """Starts the server and enters the main event loop."""
        self.tun_fd = netio.create_tun_device(ip_addr=self.config['tunnel_ip'])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.listen_addr, self.listen_port))
        logger.info(f"Server listening on {self.listen_addr}:{self.listen_port}")

        inputs = [self.sock, self.tun_fd]

        try:
            while True:
                readable, _, _ = select.select(inputs, [], [])
                for r in readable:
                    if r is self.sock:
                        self.handle_udp_packet()
                    elif r is self.tun_fd:
                        self.handle_tun_packet()
        except KeyboardInterrupt:
            logger.info("Shutting down server.")
        finally:
            self.sock.close()
            if self.tun_fd:
                os.close(self.tun_fd)

    def handle_udp_packet(self):
        """Handles a packet received from the UDP socket."""
        payload, client_addr = self.sock.recvfrom(2048)
        msg_type = proto.get_msg_type(payload)

        if msg_type == proto.MSG_INIT:
            self.handle_msg_init(payload, client_addr)
        elif msg_type == proto.MSG_INIT_WITH_COOKIE:
            self.handle_msg_init_with_cookie(payload, client_addr)
        elif msg_type == proto.MSG_DATA:
            self.handle_msg_data(payload, client_addr)
        else:
            logger.warning(f"Received invalid message type {msg_type} from {client_addr}")

    def handle_tun_packet(self):
        """Handles a packet received from the TUN device."""
        packet = netio.read_from_tun(self.tun_fd)
        # For simplicity, this server only supports one client.
        # A real server would need to determine which client to send to.
        if self.sessions:
            client_addr = list(self.sessions.keys())[0]
            session = self.sessions[client_addr]
            
            seq = session.next_tx_seq()
            nonce = seq.to_bytes(24, 'big') # TODO: Use a proper nonce
            ciphertext = session.encryptor.encrypt(packet, nonce)
            
            msg = proto.pack_msg_data(seq, ciphertext)
            self.sock.sendto(msg, client_addr)

    def handle_msg_init(self, payload, client_addr):
        """Handles an initial handshake message."""
        logger.info(f"Received MSG_INIT from {client_addr}. Sending cookie challenge.")
        cookie, timestamp = self.cookie_manager.generate_cookie(client_addr)
        response = proto.pack_msg_cookie_challenge(cookie, timestamp)
        self.sock.sendto(response, client_addr)

    def handle_msg_init_with_cookie(self, payload, client_addr):
        """Handles a handshake message that includes a cookie."""
        try:
            cookie, client_eph_pubkey_bytes = proto.unpack_msg_init_with_cookie(payload)
            client_eph_pubkey = PublicKey(client_eph_pubkey_bytes)
            
            # TODO: This is not how the cookie should be verified.
            # The original MSG_INIT payload should be part of the HMAC.
            # This is a simplified implementation for the student project.
            if not self.cookie_manager.verify_cookie(cookie, 0, client_addr):
                 return

            logger.info(f"Cookie verified for {client_addr}. Completing handshake.")
            
            eph_privkey = crypto.generate_ephemeral_keys()
            
            rx_key, tx_key = crypto.derive_keys(
                self.static_privkey, self.client_static_pubkey, self.client_static_pubkey,
                eph_privkey, client_eph_pubkey, is_client=False
            )

            self.sessions[client_addr] = Session(client_addr, tx_key, rx_key)
            
            response = proto.pack_msg_resp(eph_privkey.public_key)
            self.sock.sendto(response, client_addr)
            
        except Exception as e:
            logger.error(f"Error handling MSG_INIT_WITH_COOKIE: {e}")

    def handle_msg_data(self, payload, client_addr):
        """Handles an encrypted data message."""
        if client_addr not in self.sessions:
            logger.warning(f"Received data from unknown client {client_addr}")
            return

        session = self.sessions[client_addr]
        try:
            seq, ciphertext = proto.unpack_msg_data(payload)
            
            if not session.replay_window.accept(seq):
                return

            nonce = seq.to_bytes(24, 'big') # TODO: Use a proper nonce
            plaintext = session.decryptor.decrypt(ciphertext, nonce)
            netio.write_to_tun(self.tun_fd, plaintext)
            
        except Exception as e:
            logger.error(f"Error handling MSG_DATA: {e}")

if __name__ == '__main__':
    # This is a placeholder for running the server via CLI
    # Example usage:
    # config = {'listen_addr': '0.0.0.0', 'listen_port': 51820, ...}
    # server = Server(config)
    # server.run()
    pass
