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
        self.config = config
        self.listen_addr = (config['listen_addr'], config['listen_port'])
        self.cookie_manager = CookieManager(os.urandom(32)) # TODO: Use a persistent secret
        self.sessions = {} # Maps (ip, port) -> Session
        self.routing_table = {} # Maps tunnel_ip -> Session
        self.authorized_clients = {} # Maps static_pubkey -> tunnel_ip

        # Load authorized clients from config
        for client_config in config.get('clients', []):
            try:
                pubkey = crypto.load_key(client_config['public_key_file'])
                self.authorized_clients[pubkey] = client_config['tunnel_ip']
            except FileNotFoundError:
                log.log_error(f"Client public key file not found: {client_config['public_key_file']}")
            except KeyError:
                log.log_error(f"Invalid client configuration entry: {client_config}")
        
        if not self.authorized_clients:
            log.log_error("No authorized clients were loaded. Check the server configuration.")
            exit(1)
        
        log.log_info(f"Loaded {len(self.authorized_clients)} authorized client(s).")

        self.tun_fd = -1

        try:
            self.static_privkey = PrivateKey(crypto.load_key(config['private_key_file']))
            log.log_info("Server static key loaded successfully.")
        except FileNotFoundError:
            log.log_error(f"Server key file not found at '{config['private_key_file']}'!")
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

        tun_name = "pytunnel0" # TODO: Make configurable
        tun_ip = self.config['tunnel_ip']

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
            # Extract destination IP from the IP header (bytes 16-19)
            if len(plaintext) >= 20:
                dest_ip_bytes = plaintext[16:20]
                dest_ip_str = socket.inet_ntoa(dest_ip_bytes)
                
                session = self.routing_table.get(dest_ip_str)
                if session:
                    log.log_info(f"Found route for {dest_ip_str} -> {session.client_addr}")
                    encrypted_payload = session.encryptor.encrypt(plaintext)
                    msg = proto.pack_msg_data(encrypted_payload)
                    sock.sendto(msg, session.client_addr)
                    log.log_sent(f"MSG_DATA to {session.client_addr}")
                else:
                    log.log_error(f"No route found for destination IP: {dest_ip_str}")
            else:
                log.log_error("Received a packet from TUN that was too short to be an IP packet.")

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

            # Verify client_static_pubkey against the allowlist
            if client_static_pubkey not in self.authorized_clients:
                log.log_error(f"Unauthorized public key from {client_addr}. Ignoring.")
                return
            
            tunnel_ip = self.authorized_clients[client_static_pubkey]
            log.log_info(f"Client {client_addr} authorized for tunnel IP {tunnel_ip}")


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

            session = Session(client_addr, tx_key, rx_key, tunnel_ip)
            self.sessions[client_addr] = session
            self.routing_table[tunnel_ip] = session
            log.log_info(f"Session created for {client_addr[0]}:{client_addr[1]} with tunnel IP {tunnel_ip}")

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
