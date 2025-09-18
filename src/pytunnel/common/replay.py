"""
Replay attack prevention using a sliding window bitmap.

Each data message contains a sequence number. The receiver keeps track of
the highest sequence number seen so far and a bitmap of the last 64
packets. This allows for some out-of-order delivery while still
rejecting duplicate or very old packets.
"""
import logging

logger = logging.getLogger(__name__)

class ReplayWindow:
    def __init__(self, window_size=64):
        self.window_size = window_size
        self.max_seq = -1
        self.bitmap = 0

    def accept(self, seq):
        """
        Checks if a sequence number is valid and updates the window.
        Returns True if the packet should be accepted, False otherwise.
        """
        if seq > self.max_seq:
            shift = seq - self.max_seq
            if shift < self.window_size:
                self.bitmap <<= shift
                self.bitmap |= 1
            else:
                self.bitmap = 1
            self.max_seq = seq
            return True

        diff = self.max_seq - seq
        if diff >= self.window_size:
            logger.warning(f"Rejecting too old sequence number: {seq} (max: {self.max_seq})")
            return False

        if (self.bitmap >> diff) & 1:
            logger.warning(f"Rejecting duplicate sequence number: {seq}")
            return False

        self.bitmap |= (1 << diff)
        return True
