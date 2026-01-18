"""Tests for crypto functions."""
from core.crypto import generate_psk, generate_nonce, PSK_SIZE, NONCE_SIZE

def test_generate_psk_returns_correct_size():
    """PSK should be exactly 32 bytes."""
    psk = generate_psk()
    assert len(psk) == PSK_SIZE
    assert type(psk) == bytes

def test_generate_psk_returns_different_keys():
    """Each PSK should be random (different every time)."""
    psk1 = generate_psk()
    psk2 = generate_psk()
    assert psk1 != psk2  # Extremely unlikely to be equal
    
def test_generate_nonce_returns_correct_size():
    """Nonce should be exactly 24 bytes."""
    nonce = generate_nonce()
    assert len(nonce) == NONCE_SIZE

def test_generate_nonce_returns_different_values():
    """Each nonce should be random."""
    nonce1 = generate_nonce()
    nonce2 = generate_nonce()
    assert nonce1 != nonce2