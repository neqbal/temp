"""
The main PyTunnel client implementation.

The client initiates the handshake, manages the session with the server,
and forwards packets between the TUN device and the UDP socket.
"""
import socket
import logging
import select
import os
from nacl.public import PrivateKey, PublicKey

from ..common import proto, crypto, netio
from ..common.replay import ReplayWindow

logger = logging.getLogger(__name__)

class Client:
    def __init__(self, config):
        self.config = config
        self.server_addr = config['server_addr']
        self.server_port = config['server_port']
        self.static_privkey = PrivateKey(crypto.load_key(config['private_key_file']))
        self.server_static_pubkey = PublicKey(crypto.load_key(config['server_public_key_file']))
        self.tun_fd = None
        self.sock = None
        self.encryptor = None
        self.decryptor = None
        self.replay_window = ReplayWindow()
        self.tx_seq = 0

    def run(self):
        """Starts the client and enters the main event loop."""
        self.tun_fd = netio.create_tun_device(ip_addr=self.config['tunnel_ip'])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        self.handshake()

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
            logger.info("Shutting down client.")
        finally:
            self.sock.close()
            if self.tun_fd:
                os.close(self.tun_fd)

    def handshake(self):
        """Performs the handshake with the server."""
        logger.info("Starting handshake...")
        
        # Step 1: Send MSG_INIT
        eph_privkey = crypto.generate_ephemeral_keys()
        msg_init = proto.pack_msg_init(eph_privkey.public_key)
        self.sock.sendto(msg_init, (self.server_addr, self.server_port))
        
        # Step 2: Receive MSG_COOKIE_CHALLENGE
        payload, _ = self.sock.recvfrom(2048)
        if proto.get_msg_type(payload) != proto.MSG_COOKIE_CHALLENGE:
            raise Exception("Expected cookie challenge")
        cookie, _ = proto.unpack_msg_cookie_challenge(payload)
        logger.info("Received cookie challenge.")
        
        # Step 3: Send MSG_INIT_WITH_COOKIE
        msg_init_cookie = proto.pack_msg_init_with_cookie(cookie, eph_privkey.public_key)
        self.sock.sendto(msg_init_cookie, (self.server_addr, self.server_port))
        
        # Step 4: Receive MSG_RESP and derive keys
        payload, _ = self.sock.recvfrom(2048)
        if proto.get_msg_type(payload) != proto.MSG_RESP:
            raise Exception("Expected handshake response")
        server_eph_pubkey_bytes = proto.unpack_msg_resp(payload)
        server_eph_pubkey = PublicKey(server_eph_pubkey_bytes)
        
        tx_key, rx_key = crypto.derive_keys(
            self.static_privkey, self.server_static_pubkey, self.server_static_pubkey,
            eph_privkey, server_eph_pubkey, is_client=True
        )
        
        self.encryptor = crypto.Encryptor(tx_key)
        self.decryptor = crypto.Decryptor(rx_key)
        
        logger.info("Handshake successful. Tunnel is up.")

    def handle_udp_packet(self):
        """Handles a packet received from the UDP socket."""
        payload, _ = self.sock.recvfrom(2048)
        if proto.get_msg_type(payload) == proto.MSG_DATA:
            try:
                seq, ciphertext = proto.unpack_msg_data(payload)
                if not self.replay_window.accept(seq):
                    return
                
                nonce = seq.to_bytes(24, 'big') # TODO: Use a proper nonce
                plaintext = self.decryptor.decrypt(ciphertext, nonce)
                netio.write_to_tun(self.tun_fd, plaintext)
            except Exception as e:
                logger.error(f"Error handling MSG_DATA: {e}")

    def handle_tun_packet(self):
        """Handles a packet received from the TUN device."""
        packet = netio.read_from_tun(self.tun_fd)
        
        seq = self.tx_seq
        self.tx_seq += 1
        
        nonce = seq.to_bytes(24, 'big') # TODO: Use a proper nonce
        ciphertext = self.encryptor.encrypt(packet, nonce)
        
        msg = proto.pack_msg_data(seq, ciphertext)
        self.sock.sendto(msg, (self.server_addr, self.server_port))

if __name__ == '__main__':
    # Placeholder for running the client via CLI
    pass
