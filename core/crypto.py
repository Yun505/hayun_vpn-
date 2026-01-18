"""
Core cryptographic functions for MST VPN.
Uses PyNaCl (libsodium) for secure random byte generation.
"""
from nacl.utils import random

# Constants - these define sizes in bytes
PSK_SIZE = 32  # 256 bits = 32 bytes (standard for ChaCha20)
NONCE_SIZE = 24  # PyNaCl SecretBox uses 24-byte nonces

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