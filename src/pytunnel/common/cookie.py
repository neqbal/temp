"""
Stateless cookie generation and verification for DDoS mitigation.

The server, upon receiving an initial handshake message from an unknown IP,
does not allocate any state. Instead, it replies with a cookie challenge.
The cookie is an HMAC of the client's IP, port, and a timestamp, signed
with a server-side secret. The client must return this cookie in its next
message.
"""
import hmac
import hashlib
import time
import logging

logger = logging.getLogger(__name__)

# Constants
COOKIE_SECRET = b'a-very-secret-cookie-key' # TODO: Should be rotated and not hardcoded
COOKIE_TTL = 10  # seconds
COOKIE_LEN = 16

class CookieManager:
    def __init__(self, secret=COOKIE_SECRET):
        self.secret = secret

    def generate_cookie(self, client_addr):
        """Generates a stateless cookie for a client address."""
        timestamp = int(time.time())
        ip, port = client_addr
        
        # The message to HMAC includes the client's address, a timestamp,
        # and the server's secret to prevent tampering.
        message = f"{ip}:{port}:{timestamp}".encode('utf-8')
        
        h = hmac.new(self.secret, message, hashlib.sha256)
        return h.digest()[:COOKIE_LEN], timestamp

    def verify_cookie(self, cookie, timestamp, client_addr):
        """Verifies a cookie from a client."""
        if time.time() - timestamp > COOKIE_TTL:
            logger.warning(f"Expired cookie from {client_addr}")
            return False

        expected_cookie, _ = self.generate_cookie(client_addr)
        
        if not hmac.compare_digest(cookie, expected_cookie):
            logger.warning(f"Invalid cookie from {client_addr}")
            return False
            
        return True
