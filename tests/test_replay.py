""""Tests for replay protection sliding window."""

import pytest
from core.replay import SlidingWindow


def test_window_accepts_first_packet():
    """First packet should always be accepted."""
    window = SlidingWindow(window_size=64)
    assert window.should_accept(1) == True


def test_window_rejects_duplicate():
    """Duplicate packet should be rejected."""
    window = SlidingWindow(window_size=64)
    assert window.should_accept(5) == True
    window.mark_received(5)
    assert window.should_accept(5) == False


def test_window_accepts_in_order_packets():
    """Sequential packets should be accepted."""
    window = SlidingWindow(window_size=64)
    for i in range(1, 10):
        assert window.should_accept(i) == True
        window.mark_received(i)


def test_window_accepts_out_of_order_within_window():
    """Out-of-order packets within window should be accepted."""
    window = SlidingWindow(window_size=64)
    packets = [5, 3, 7, 1, 4, 6, 2]
    for seq in packets:
        assert window.should_accept(seq) == True
        window.mark_received(seq)


def test_window_rejects_old_packets():
    """Packets that fell out of window should be rejected."""
    window = SlidingWindow(window_size=8)
    for i in range(1, 11):
        window.mark_received(i)
    assert window.should_accept(1) == False
    assert window.should_accept(2) == False
    assert window.should_accept(11) == True


def test_window_advances_correctly():
    """Window should advance when new max is received."""
    window = SlidingWindow(window_size=8)
    window.mark_received(5)
    assert window.max_seq == 5
    window.mark_received(10)
    assert window.max_seq == 10


def test_window_large_gap():
    """Large gap should clear window."""
    window = SlidingWindow(window_size=8)
    window.mark_received(5)
    window.mark_received(100)
    assert window.max_seq == 100
    assert window.should_accept(5) == False


def test_window_boundary_cases():
    """Test edge cases at window boundaries."""
    window = SlidingWindow(window_size=8)
    for i in range(1, 9):
        window.mark_received(i)
    assert window.should_accept(1) == False
    assert window.should_accept(9) == True


def test_window_stats():
    """Test statistics reporting."""
    window = SlidingWindow(window_size=8)
    window.mark_received(3)
    window.mark_received(5)
    stats = window.get_stats()
    assert stats['window_size'] == 8
    assert stats['packets_received'] == 2


def test_window_reset():
    """Test window reset functionality."""
    window = SlidingWindow(window_size=8)
    window.mark_received(5)
    window.reset()
    assert window.base_seq == 0
    assert window.max_seq == 0


def test_sequential_with_gaps():
    """Test handling of packets with gaps."""
    window = SlidingWindow(window_size=8)
    for seq in [1, 2, 4, 5, 7]:
        window.mark_received(seq)
    assert window.should_accept(3) == True
    assert window.should_accept(6) == True


def test_realistic_scenario():
    """Test realistic packet arrival pattern."""
    window = SlidingWindow(window_size=64)
    arrival_order = [1, 2, 3, 5, 4, 6, 7, 9, 8, 10]
    for seq in arrival_order:
        assert window.should_accept(seq) == True
        window.mark_received(seq)
    for seq in range(1, 11):
        assert window.should_accept(seq) == False