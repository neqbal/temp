"""
The main PyTunnel client implementation.
"""
import socket
import os
import select
import subprocess
from ..common import crypto
from ..common import proto
from ..common import log
from ..common import tun
from nacl.public import PrivateKey, PublicKey

class Client:
    def __init__(self, config, server_addr):
        self.server_addr = server_addr
        self.config = config
        self.sock = None
        self.tun_fd = -1
        self.tx_key = None
        self.rx_key = None
        self.encryptor = None
        self.decryptor = None

        try:
            self.static_privkey = PrivateKey(crypto.load_key(config['private_key_file']))
            self.static_pubkey = self.static_privkey.public_key
            self.server_static_pubkey = PublicKey(crypto.load_key(config['server_public_key_file']))
            log.log_info("Client and server keys loaded successfully.")
        except FileNotFoundError as e:
            log.log_error(f"Key file not found: {e.filename}")
            log.log_error("Please run 'python3 scripts/genkeys.py --out-dir configs --name [server/client]' and ensure server.pub is copied to the client.")
            exit(1)
        # TODO: Initialize ReplayWindow

    def run(self):
        """Starts the client and enters the main event loop."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log.log_info(f"Connecting to server at {self.server_addr[0]}:{self.server_addr[1]}")
        
        self.handshake()
        if not self.tx_key or not self.rx_key:
            log.log_error("Handshake failed. Could not derive session keys.")
            return

        # Setup TUN device
        self.tun_fd = tun.create_tun_interface()
        if self.tun_fd < 0:
            log.log_error("Failed to create TUN interface. Exiting.")
            return
        
        tun_name = "pytunnel0" # TODO: Make configurable
        tun_ip = self.config['tunnel_ip']
        
        # This is where we would use run_shell_command, but for now, we log what we would do
        log.log_info(f"Configuring TUN device {tun_name}...")
        try:
            tun.configure_tun_interface(tun_name, tun_ip)
        except Exception as e:
            log.log_error(f"Failed to configure TUN device: {e}")
            return

        log.log_info("Entering main loop. Forwarding traffic...")
        try:
            while True:
                # Wait for I/O on the socket or the TUN device
                readable, _, _ = select.select([self.sock, self.tun_fd], [], [])
                for r in readable:
                    if r is self.sock:
                        self.handle_udp_packet()
                    if r is self.tun_fd:
                        self.handle_tun_packet()
        except KeyboardInterrupt:
            log.log_info("Client shutting down.")
        finally:
            if self.tun_fd >= 0:
                os.close(self.tun_fd)
            if self.sock:
                self.sock.close()

    def handshake(self):
        """Performs the handshake with the server."""
        # Step 1: Send MSG_INIT
        eph_privkey, eph_pubkey = crypto.generate_ephemeral_keys()
        msg = proto.pack_msg_init(bytes(eph_pubkey), bytes(self.static_pubkey))
        self.sock.sendto(msg, self.server_addr)
        log.log_sent("MSG_INIT")

        # Step 2: Receive the server's response and check its type
        response, _ = self.sock.recvfrom(4096)
        msg_type = proto.get_msg_type(response)

        server_eph_pubkey = None

        if msg_type == proto.MSG_TYPE_COOKIE_CHALLENGE:
            log.log_received("MSG_COOKIE_CHALLENGE")
            cookie, timestamp = proto.unpack_msg_cookie_challenge(response)

            # Step 3: Send MSG_INIT_WITH_COOKIE
            msg = proto.pack_msg_init_with_cookie(cookie, timestamp, bytes(eph_pubkey), bytes(self.static_pubkey))
            self.sock.sendto(msg, self.server_addr)
            log.log_sent("MSG_INIT_WITH_COOKIE")

            # Step 4: Receive MSG_RESP
            response, _ = self.sock.recvfrom(4096)
            if proto.get_msg_type(response) != proto.MSG_TYPE_RESP:
                log.log_error("Handshake error: Expected MSG_RESP after cookie challenge.")
                return
            
            server_eph_pubkey = proto.unpack_msg_resp(response)
            log.log_received("MSG_RESP")
        
        elif msg_type == proto.MSG_TYPE_RESP:
            # This is the vulnerable mode path, handshake completes in one round trip.
            log.log_received("MSG_RESP")
            log.log_info("Server appears to be in vulnerable mode (no cookie challenge).")
            server_eph_pubkey = proto.unpack_msg_resp(response)

        else:
            log.log_error(f"Handshake error: Received unexpected message type {msg_type}")
            return

        # Step 5: Derive keys and complete handshake
        self.tx_key, self.rx_key = crypto.derive_keys(
            self.static_privkey,
            self.server_static_pubkey,
            eph_privkey,
            server_eph_pubkey,
            is_client=True
        )
        
        log.log_info(f"Client TX key: {self.tx_key.hex()}")
        log.log_info(f"Client RX key: {self.rx_key.hex()}")

        self.encryptor = crypto.Encryptor(self.tx_key)
        self.decryptor = crypto.Decryptor(self.rx_key)

        log.log_info("Handshake successful. Session keys derived.")

    def handle_udp_packet(self):
        """Handles a packet received from the UDP socket (the internet)."""
        try:
            data, _ = self.sock.recvfrom(4096)
            msg_type = proto.get_msg_type(data)

            if msg_type == proto.MSG_TYPE_DATA:
                log.log_received("MSG_DATA")
                encrypted_payload = proto.unpack_msg_data(data)
                
                # TODO: Check for replays
                
                plaintext = self.decryptor.decrypt(encrypted_payload)
                os.write(self.tun_fd, plaintext)
                log.log_info(f"Wrote {len(plaintext)} bytes to TUN device.")
        except Exception as e:
            log.log_error(f"Error handling UDP packet: {e}")

    def handle_tun_packet(self):
        """Handles a packet received from the TUN device (local OS)."""
        try:
            plaintext = os.read(self.tun_fd, 4096)
            log.log_info(f"Read {len(plaintext)} bytes from TUN device.")
            
            encrypted_payload = self.encryptor.encrypt(plaintext)
            msg = proto.pack_msg_data(encrypted_payload)
            
            self.sock.sendto(msg, self.server_addr)
            log.log_sent("MSG_DATA")
        except Exception as e:
            log.log_error(f"Error handling TUN packet: {e}")
