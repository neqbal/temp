"""
Stateless cookie generation and verification for DDoS mitigation.
"""

import hmac
import os
import time

class CookieManager:
    def __init__(self, secret):
        self.secret = secret

    def generate_cookie(self, client_addr):
        """Generates a stateless cookie for a client address."""
        timestamp = int(time.time())
        ip, port = client_addr
        message = f'{ip}:{port}:{timestamp}'.encode('utf-8')
        mac = hmac.new(self.secret, message, 'sha256').digest()
        return mac, timestamp

    def verify_cookie(self, cookie, timestamp, client_addr, ttl=30):
        """Verifies a cookie from a client."""
        if time.time() - timestamp > ttl:
            return False # Expired
        
        ip, port = client_addr
        message = f'{ip}:{port}:{timestamp}'.encode('utf-8')
        expected_mac = hmac.new(self.secret, message, 'sha256').digest()
        return hmac.compare_digest(cookie, expected_mac)
