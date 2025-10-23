"""
Replay attack prevention using a sliding window bitmap.
"""

class ReplayWindow:
    def __init__(self, window_size=64):
        if not 0 < window_size <= 64:
            raise ValueError("Window size must be between 1 and 64")
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
            if shift >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = (self.bitmap << shift) | 1
            self.max_seq = seq
            return True
        
        # Packet is within the window
        elif seq > self.max_seq - self.window_size:
            shift = self.max_seq - seq
            if (self.bitmap >> shift) & 1:
                return False  # Duplicate
            else:
                self.bitmap |= (1 << shift)
                return True
        
        # Packet is too old
        else:
            return False
