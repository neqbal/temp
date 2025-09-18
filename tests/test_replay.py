import pytest
from pytunnel.common.replay import ReplayWindow

def test_replay_window_accepts_new():
    """Tests that the window accepts new, in-order sequence numbers."""
    window = ReplayWindow()
    assert window.accept(0)
    assert window.accept(1)
    assert window.accept(10)
    assert window.max_seq == 10

def test_replay_window_rejects_duplicates():
    """Tests that the window rejects duplicate sequence numbers."""
    window = ReplayWindow()
    assert window.accept(0)
    assert not window.accept(0)

def test_replay_window_accepts_out_of_order():
    """Tests that the window accepts out-of-order packets within the window."""
    window = ReplayWindow()
    window.accept(10)
    assert window.accept(5)
    assert window.accept(9)
    assert not window.accept(5) # Now it's a duplicate

def test_replay_window_rejects_too_old():
    """Tests that the window rejects packets that are too old."""
    window = ReplayWindow(window_size=64)
    window.accept(100)
    assert not window.accept(30) # 100 - 30 = 70, which is > 64
    assert window.accept(40) # 100 - 40 = 60, which is < 64
