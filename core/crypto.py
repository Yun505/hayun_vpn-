"""
Core cryptographic functions for MST VPN.
Uses PyNaCl (libsodium) for secure random byte generation.
"""
import hmac
import hashlib
from nacl.utils import random
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Constants - these define sizes in bytes
PSK_SIZE = 32  # 256 bits = 32 bytes (standard for ChaCha20)
NONCE_SIZE = 24  # PyNaCl SecretBox uses 24-byte nonces
SESSION_KEY_SIZE = 32
MAC_SIZE = 32  # HMAC-SHA256 produces 32-byte output
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
    
def compute_handshake_mac(psk, client_nonce, server_nonce):
    """
        Compute HMAC for handshake authentication.
    This function creates a "proof" that the caller knows the PSK.
    An attacker without the PSK cannot create a valid MAC.
    The MAC is computed over both nonces to:
        1. Ensure freshness (nonces are random each time)
        2. Bind this MAC to this specific handshake
        3. Prevent replay attacks (old MACs can't be reused)
    Args:
            psk (bytes): Pre-shared key (32 bytes)
            client_nonce (bytes): Client's random nonce (24 bytes)
            server_nonce (bytes): Server's random nonce (24 bytes)
        Returns:
            bytes: HMAC-SHA256 (32 bytes)
        Raises:
    ValueError: If any input has wrong length
        Security Note:
    The order of nonces in the message MUST be consistent:
            always client_nonce || server_nonce. If client and server
            use different orders, MACs won't match and handshake fails.
        """
    # Validate inputs
    if len(psk) != PSK_SIZE:
        raise ValueError(f"PSK must be {PSK_SIZE} bytes")
    if len(client_nonce) != NONCE_SIZE:
        raise ValueError(f"Client nonce must be {NONCE_SIZE} bytes")
    if len(server_nonce) != NONCE_SIZE:
        raise ValueError(f"Server nonce must be {NONCE_SIZE} bytes")
    
    # Construct the message: client nonce comes FIRST (standardized order)
    # This is the data we're "signing" with the PSK
    message = client_nonce + server_nonce  # 48 bytes total
    
    # Compute HMAC-SHA256
    # hmac.new(key, message, hash_algorithm)
    mac = hmac.new(
        psk,       # Secret key (only client and server know this)       
        message,   # Data to authenticate (both nonces)
        hashlib.sha256     # Hash function (SHA-256)
    ).digest()           # Get raw bytes (not hex string)
    
    # MAC is 32 bytes (256 bits from SHA-256)
    assert len(mac) == 32, "HMAC-SHA256 should produce 32 bytes"
    
    return mac

def verify_handshake_mac(psk, client_nonce, server_nonce, received_mac):
    """
    Verify a handshake MAC is correct.
    
    This checks if the received MAC matches what we expect.
    If MACs match: other side knows the PSK (authentic!)
    If MACs don't match: other side doesn't know PSK (imposter!)
    
    Args:
        psk (bytes): Pre-shared key (32 bytes)
        client_nonce (bytes): Client's nonce (24 bytes)
        server_nonce (bytes): Server's nonce (24 bytes)
        received_mac (bytes): MAC received from other side (32 bytes)
        
    Returns:
        bool: True if MAC is valid, False otherwise
        
    Security Critical:
        Uses timing-safe comparison to prevent timing attacks.
        Regular comparison (==) might leak information about
        how many bytes matched, helping attackers guess the MAC.
    """
    # Validate received MAC length
    if len(received_mac) != MAC_SIZE:
        # Don't even try to verify if wrong size
        return False
    
    # Compute what the MAC SHOULD be
    expected_mac = compute_handshake_mac(psk, client_nonce, server_nonce)
    
    # Compare using timing-safe function
    # hmac.compare_digest() takes same time regardless of how many bytes match
    # Regular comparison (==) returns faster if first bytes don't match
    is_valid = hmac.compare_digest(received_mac, expected_mac)
    
    return is_valid
