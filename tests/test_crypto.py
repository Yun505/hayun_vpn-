"""Tests for crypto functions."""
import pytest
from nacl.exceptions import CryptoError

from core.crypto import (
    generate_psk, generate_nonce, derive_session_key, encrypt_data, decrypt_data,
    PSK_SIZE, NONCE_SIZE, SESSION_KEY_SIZE
)
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
def test_derive_session_key_returns_correct_size():
    """Session key should be 32 bytes."""
    psk = generate_psk()
    client_nonce = generate_nonce()
    server_nonce = generate_nonce()
    session_key = derive_session_key(psk, client_nonce, server_nonce)
    assert len(session_key) == SESSION_KEY_SIZE
def test_derive_session_key_is_deterministic():
    """Same inputs should always produce same session key."""
    psk = generate_psk()
    client_nonce = generate_nonce()
    server_nonce = generate_nonce()
    key1 = derive_session_key(psk, client_nonce, server_nonce)
    key2 = derive_session_key(psk, client_nonce, server_nonce)
    assert key1 == key2  # Must be identical
def test_derive_session_key_different_nonces_produce_different_keys():
    """Changing nonces should produce different session keys."""
    psk = generate_psk()
    client_nonce1 = generate_nonce()
    client_nonce2 = generate_nonce()
    server_nonce = generate_nonce()
    key1 = derive_session_key(psk, client_nonce1, server_nonce)
    key2 = derive_session_key(psk, client_nonce2, server_nonce)
    assert key1 != key2  # Different nonces = different keys
def test_derive_session_key_validates_psk_length():
    """Should raise ValueError if PSK has wrong length."""
    bad_psk = b"too short"
    client_nonce = generate_nonce()
    server_nonce = generate_nonce()
    with pytest.raises(ValueError):
        derive_session_key(bad_psk, client_nonce, server_nonce)
def test_encrypt_decrypt_roundtrip():
    """Encrypt then decrypt should return original plaintext."""
    psk = generate_psk()
    session_key = derive_session_key(psk, generate_nonce(), generate_nonce())
    nonce = generate_nonce()
    plaintext = b"Hello, VPN!"
    
    ciphertext = encrypt_data(session_key, plaintext, nonce)
    decrypted = decrypt_data(session_key, ciphertext, nonce)
    
    assert decrypted == plaintext

def test_ciphertext_is_different_from_plaintext():
    """Ciphertext should not equal plaintext (basic encryption check)."""
    psk = generate_psk()
    session_key = derive_session_key(psk, generate_nonce(), generate_nonce())
    nonce = generate_nonce()
    plaintext = b"Secret message"
    
    ciphertext = encrypt_data(session_key, plaintext, nonce)
    
    assert ciphertext != plaintext
    assert len(ciphertext) > len(plaintext)  # Has auth tag

def test_decrypt_with_wrong_key_fails():
    """Decryption with different key should fail."""
    psk = generate_psk()
    key1 = derive_session_key(psk, generate_nonce(), generate_nonce())
    key2 = derive_session_key(psk, generate_nonce(), generate_nonce())
    nonce = generate_nonce()
    plaintext = b"Secret"
    
    ciphertext = encrypt_data(key1, plaintext, nonce)
    
    with pytest.raises(CryptoError):
        decrypt_data(key2, ciphertext, nonce)

def test_decrypt_tampered_ciphertext_fails():
    """Modified ciphertext should fail authentication."""
    psk = generate_psk()
    session_key = derive_session_key(psk, generate_nonce(), generate_nonce())
    nonce = generate_nonce()
    plaintext = b"Secret message"
    
    ciphertext = encrypt_data(session_key, plaintext, nonce)
    
    # Tamper with the ciphertext
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0xFF  # Flip bits at position 5
    tampered = bytes(tampered)
    
    with pytest.raises(CryptoError):
        decrypt_data(session_key, tampered, nonce)