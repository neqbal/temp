"""
Stateless cookie generation and verification for DDoS mitigation.
"""

class CookieManager:
    def __init__(self, secret):
        # TODO: Store the cookie secret
        pass

    def generate_cookie(self, client_addr):
        """Generates a stateless cookie for a client address."""
        # TODO: Get current timestamp
        # TODO: Create message to HMAC (e.g., ip:port:timestamp)
        # TODO: Compute HMAC and return cookie and timestamp
        pass

    def verify_cookie(self, cookie, timestamp, client_addr):
        """Verifies a cookie from a client."""
        # TODO: Check if timestamp is within TTL
        # TODO: Regenerate the expected cookie
        # TODO: Compare the received cookie with the expected one using hmac.compare_digest
        # TODO: Return True or False
        pass
