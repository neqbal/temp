import pytest
from src.pytunnel.common.replay import ReplayWindow

def test_replay_window_basic():
    """Tests the replay window logic with sequential packets."""
    replay_window = ReplayWindow()
    assert replay_window.accept(0)
    assert replay_window.accept(1)
    assert replay_window.accept(2)
    assert not replay_window.accept(1) # Duplicate
    assert not replay_window.accept(0) # Duplicate

def test_replay_window_out_of_order():
    """Tests accepting out-of-order packets within the window."""
    replay_window = ReplayWindow(window_size=10)
    assert replay_window.accept(5)
    assert replay_window.accept(3)
    assert replay_window.accept(4)
    assert not replay_window.accept(3) # Duplicate
    assert replay_window.accept(0)
    assert not replay_window.accept(0) # Duplicate

def test_replay_window_old_packets():
    """Tests rejecting packets that are too old."""
    replay_window = ReplayWindow(window_size=5)
    replay_window.accept(10)
    assert not replay_window.accept(4) # Too old
    assert not replay_window.accept(5) # Too old
    assert replay_window.accept(6)

def test_replay_window_slide():
    """Tests the sliding window mechanism."""
    replay_window = ReplayWindow(window_size=4)
    replay_window.accept(0)
    replay_window.accept(1)
    replay_window.accept(2)
    replay_window.accept(3)
    assert not replay_window.accept(0)

    replay_window.accept(4) # Window slides
    assert not replay_window.accept(0) # Now too old
    assert replay_window.accept(1) # Still in window

def test_large_jump():
    """Tests a large jump in sequence numbers."""
    replay_window = ReplayWindow(window_size=64)
    replay_window.accept(0)
    replay_window.accept(100)
    assert not replay_window.accept(30) # Too old
    assert replay_window.accept(101)
    assert not replay_window.accept(100) # Duplicate
