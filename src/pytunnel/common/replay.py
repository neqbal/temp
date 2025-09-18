"""
Replay attack prevention using a sliding window bitmap.
"""

class ReplayWindow:
    def __init__(self, window_size=64):
        # TODO: Initialize max_seq and bitmap
        pass

    def accept(self, seq):
        """
        Checks if a sequence number is valid and updates the window.
        """
        # TODO: If seq > max_seq, shift window and accept
        # TODO: If seq is within the window, check bitmap
        # TODO: If not a duplicate, set bit in bitmap and accept
        # TODO: If it's a duplicate or too old, reject
        pass
