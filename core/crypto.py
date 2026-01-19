"""
Core cryptographic functions for MST VPN.
Uses PyNaCl (libsodium) for secure random byte generation.
"""
from nacl.utils import random
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Constants - these define sizes in bytes
PSK_SIZE = 32  # 256 bits = 32 bytes (standard for ChaCha20)
NONCE_SIZE = 24  # PyNaCl SecretBox uses 24-byte nonces
SESSION_KEY_SIZE = 32
HKDF_INFO= b'MST-v1-session-key'
def generate_psk():
    """
    Generate a cryptographically secure pre-shared key.
    
    This is like creating a super strong password made of random bytes.
    You'll save this to a file and share it between client/server.
    
    Returns:
        bytes: 32 random bytes
        
    Example:
        >>> psk = generate_psk()
        >>> len(psk)
        32
        >>> type(psk)
        <class 'bytes'>
    """
    return random(PSK_SIZE)

def generate_nonce():
    """
    Generate a random nonce (number used once).
    
    A nonce is like a unique serial number. It prevents replay attacks
    and ensures the same message encrypted twice looks different.
    
    Returns:
        bytes: 24 random bytes
        
    Example:
        >>> nonce = generate_nonce()
        >>> len(nonce)
        24
    """
    return random(NONCE_SIZE)


def derive_session_key(psk, client_nonce, server_nonce):
    """Derive session key using HKDF-SHA256."""
    if len(psk) != PSK_SIZE:
        raise ValueError(f"PSK must be {PSK_SIZE} bytes, got {len(psk)}")
    if len(client_nonce) != NONCE_SIZE:
        raise ValueError(f"Client nonce must be {NONCE_SIZE} bytes")
    if len(server_nonce) != NONCE_SIZE:
        raise ValueError(f"Server nonce must be {NONCE_SIZE} bytes")
    
    salt = client_nonce + server_nonce
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO
    )
    
    session_key = hkdf.derive(psk)
    return session_key
def encrypt_data(session_key, plaintext, nonce):
    """Encrypt data using ChaCha20-Poly1305 AEAD."""
    if len(session_key) != SESSION_KEY_SIZE:
        raise ValueError(f"Session key must be {SESSION_KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
    
    box = SecretBox(session_key)
    encrypted = box.encrypt(plaintext, nonce)
    
    # Strip nonce from output (we track it separately)
    ciphertext_with_tag = encrypted[NONCE_SIZE:]
    return ciphertext_with_tag

def decrypt_data(session_key, ciphertext, nonce):
    """Decrypt and verify data using ChaCha20-Poly1305 AEAD."""
    if len(session_key) != SESSION_KEY_SIZE:
        raise ValueError(f"Session key must be {SESSION_KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
    
    box = SecretBox(session_key)
    
    # Reconstruct full encrypted message (nonce + ciphertext)
    full_encrypted = nonce + ciphertext
    
    try:
        plaintext = box.decrypt(full_encrypted)
        return plaintext
    except CryptoError:
        raise CryptoError("Decryption failed: data may be tampered")