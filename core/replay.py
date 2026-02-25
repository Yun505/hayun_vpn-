"""
Replay protection using sliding window algorithm.

Prevents attackers from replaying captured packets.
"""


class SlidingWindow:
    """
    Sliding window for tracking received packets.
    
    Design:
    - Tracks window of recent packet sequence numbers
    - Accepts new packets and packets within window
    - Rejects old packets that fell out of window
    - Rejects duplicate packets (already received)
    
    Why 64 packets?
    - Balance between memory usage and reordering tolerance
    - WireGuard uses 2048, we use 64 for simplicity
    - Allows up to 64 packets to arrive out-of-order
    
    Algorithm: Bitmap-based sliding window
    - More memory efficient than set-based approach
    - O(1) lookup and update operations
    - Automatically discards old packets as window advances
    """
    
    def __init__(self, window_size=64):
        """
        Initialize sliding window.
        
        Args:
            window_size (int): Number of packets to track (default 64)
        """
        self.window_size = window_size
        self.bitmap = [False] * window_size
        self.base_seq = 0
        self.max_seq = 0
    
    def should_accept(self, seq_num):
        """
        Check if packet with sequence number should be accepted.
        
        Args:
            seq_num (int): Packet sequence number
            
        Returns:
            bool: True if packet should be accepted, False if rejected
        """
        # Case 1: Brand new packet
        if seq_num > self.max_seq:
            return True
        
        # Case 2: Too old (fell out of window)
        if seq_num < self.base_seq:
            return False
        
        # Case 3: Within window - check if duplicate
        index = (seq_num - self.base_seq) % self.window_size
        
        if self.bitmap[index]:
            return False  # Duplicate!
        
        return True
    
    def mark_received(self, seq_num):
        """
        Mark packet as received and advance window if needed.
        
        Args:
            seq_num (int): Packet sequence number
        """
        # Update max if this is a new maximum
        if seq_num > self.max_seq:
            self.max_seq = seq_num
        
        # Only advance window if max_seq has gone beyond window range
        # Window covers [base_seq, base_seq + window_size - 1]
        # Advance when max_seq >= base_seq + window_size
        if self.max_seq >= self.base_seq + self.window_size:
            # Calculate how much to shift to fit max_seq in window
            new_base = self.max_seq - self.window_size + 1
            shift = new_base - self.base_seq
            
            if shift >= self.window_size:
                # Massive jump - clear entire window
                self.bitmap = [False] * self.window_size
                self.base_seq = new_base
            else:
                # Normal advance
                self._advance_window(shift)
        
        # Mark this packet as received in bitmap
        if seq_num >= self.base_seq:
            index = (seq_num - self.base_seq) % self.window_size
            self.bitmap[index] = True
    def _advance_window(self, shift):
        """
        Advance window by 'shift' positions.
        
        Args:
            shift (int): Number of positions to advance
        """
        # Create new bitmap
        new_bitmap = [False] * self.window_size
        
        # Copy old values that are still in window
        for i in range(self.window_size):
            old_index = i + shift
            if old_index < self.window_size:
                new_bitmap[i] = self.bitmap[old_index]
        
        self.bitmap = new_bitmap
        self.base_seq += shift
    
    def get_stats(self):
        """
        Get window statistics (for debugging/testing).
        
        Returns:
            dict: Window statistics
        """
        return {
            'window_size': self.window_size,
            'base_seq': self.base_seq,
            'max_seq': self.max_seq,
            'packets_received': sum(self.bitmap),
            'coverage': f"{self.base_seq} - {self.base_seq + self.window_size - 1}"
        }
    
    def reset(self):
        """
        Reset window to initial state.
        """
        self.bitmap = [False] * self.window_size
        self.base_seq = 0
        self.max_seq = 0

