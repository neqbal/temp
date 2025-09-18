import pytest
import time
from pytunnel.common.cookie import CookieManager

def test_cookie_generation_and_verification():
    """Tests that a generated cookie can be successfully verified."""
    manager = CookieManager(secret=b'test-secret')
    client_addr = ('127.0.0.1', 12345)
    
    cookie, timestamp = manager.generate_cookie(client_addr)
    
    assert manager.verify_cookie(cookie, timestamp, client_addr)

def test_invalid_cookie():
    """Tests that a tampered cookie is rejected."""
    manager = CookieManager(secret=b'test-secret')
    client_addr = ('127.0.0.1', 12345)
    
    cookie, timestamp = manager.generate_cookie(client_addr)
    
    invalid_cookie = b'\x00' * 16
    assert not manager.verify_cookie(invalid_cookie, timestamp, client_addr)

def test_expired_cookie():
    """Tests that an expired cookie is rejected."""
    manager = CookieManager(secret=b'test-secret')
    client_addr = ('127.0.0.1', 12345)
    
    cookie, timestamp = manager.generate_cookie(client_addr)
    
    # Simulate time passing
    expired_timestamp = timestamp - (manager.COOKIE_TTL + 1)
    
    assert not manager.verify_cookie(cookie, expired_timestamp, client_addr)
