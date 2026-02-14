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
class HandshakeState:
    """
    Track handshake state for client or server.
    
    States:
    - INIT: Handshake not started
    - WAITING_RESPONSE: Client sent init, waiting for server
    - WAITING_CONFIRM: Server sent response, waiting for client confirm
    - CONFIRMED: Handshake complete, session key established
    - FAILED: Handshake failed (authentication error, timeout, etc.)
    
    Design Note:
        Why use a class instead of just variables?
        - Encapsulation: All handshake state in one place
        - Methods can enforce valid state transitions
        - Easier to reset/debug
        - Can add timeout tracking later
    """
    INIT = "INIT"
    WAITING_RESPONSE = "WAITING_RESPONSE"
    WAITING_CONFIRM = "WAITING_CONFIRM"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    
    def __init__(self):
        self.state = self.INIT
        self.client_nonce = None
        self.server_nonce = None
        self.session_key = None
    
    def is_complete(self):
        """Check if handshake is successfully completed."""
        return self.state == self.CONFIRMED
    
    def has_failed(self):
        """Check if handshake has failed."""
        return self.state == self.FAILED


def handshake_client_init(psk):
    """
    CLIENT STEP 1: Initiate handshake.
    
    Generate a random nonce and build init packet.
    
    Args:
        psk (bytes): Pre-shared key
        
    Returns:
        tuple: (packet_bytes, handshake_state)
        - packet_bytes: Init packet to send to server
        - handshake_state: State object to track progress
        
    Design Rationale:
        Why return both packet AND state?
        - Packet: What to send on network
        - State: What to remember for next steps
        
        Alternative: Return just packet, let caller track state
        - Easy to lose state
        - Caller has to know internals
        
        Better: Return both
        - Self-contained
        - Caller just needs to store state object
    """
    # Generate random nonce
    # Why random? Ensures uniqueness even if PSK is reused
    client_nonce = generate_nonce()
    
    # Build packet
    from core.protocol import build_handshake_init_packet
    packet = build_handshake_init_packet(client_nonce)
    
    # Create state object to track handshake progress
    state = HandshakeState()
    state.state = HandshakeState.WAITING_RESPONSE
    state.client_nonce = client_nonce
    # server_nonce and session_key still None (don't have them yet)
    
    return packet, state


def handshake_client_process_response(psk, state, response_packet):
    """
    CLIENT STEP 2: Process server's response.
    
    Verify server's MAC, then send confirmation.
    
    Args:
        psk (bytes): Pre-shared key
        state (HandshakeState): State from init
        response_packet (bytes): Server's response packet
        
    Returns:
        tuple: (confirm_packet, updated_state)
        - confirm_packet: Confirmation to send to server (or None if failed)
        - updated_state: Updated state object
        
    Raises:
        ValueError: If handshake state is wrong
        
    Design Critical:
        This function performs AUTHENTICATION.
        If MAC verification fails, we ABORT immediately.
        Never proceed with untrusted server!
    """
    # Validate we're in correct state
    if state.state != HandshakeState.WAITING_RESPONSE:
        raise ValueError(f"Wrong state for processing response: {state.state}")
    
    # Parse server's response
    from core.protocol import parse_handshake_response_packet
    try:
        parsed = parse_handshake_response_packet(response_packet)
    except Exception as e:
        # Malformed packet - handshake fails
        state.state = HandshakeState.FAILED
        return None, state
    
    server_nonce = parsed['server_nonce']
    server_mac = parsed['mac']
    
    # CRITICAL SECURITY CHECK: Verify server's MAC
    # This proves server knows the PSK
    is_valid = verify_handshake_mac(
        psk,
        state.client_nonce,  # We sent this in step 1
        server_nonce,        # Server just sent this
        server_mac           # Server's proof it knows PSK
    )
    
    if not is_valid:
        # MAC doesn't match - server doesn't know PSK!
        # This could be:
        # - Wrong PSK configured
        # - Man-in-the-middle attack
        # - Network corruption
        # Either way: ABORT!
        state.state = HandshakeState.FAILED
        return None, state
    
    # MAC is valid - server is authentic!
    # Store server's nonce
    state.server_nonce = server_nonce
    
    # Derive session key
    # Both client and server will compute this same key
    session_key = derive_session_key(psk, state.client_nonce, server_nonce)
    state.session_key = session_key
    
    # Compute our own MAC to prove WE know the PSK
    client_mac = compute_handshake_mac(psk, state.client_nonce, server_nonce)
    
    # Build confirmation packet
    from core.protocol import build_handshake_confirm_packet
    confirm_packet = build_handshake_confirm_packet(client_mac)
    
    # Update state
    state.state = HandshakeState.CONFIRMED
    
    return confirm_packet, state


def handshake_server_process_init(psk, init_packet):
    """
    SERVER STEP 1: Process client's init, send response.
    
    Args:
        psk (bytes): Pre-shared key
        init_packet (bytes): Client's init packet
        
    Returns:
        tuple: (response_packet, handshake_state)
        - response_packet: Response to send to client
        - handshake_state: State to track handshake
        
    Design Note:
        Server doesn't send first, so no separate "init" function.
        This is the server's first handshake action.
    """
    # Parse client's init
    from core.protocol import parse_handshake_init_packet
    try:
        parsed = parse_handshake_init_packet(init_packet)
    except Exception as e:
        # Malformed packet - can't proceed
        return None, None
    
    client_nonce = parsed['client_nonce']
    
    # Generate server's nonce
    server_nonce = generate_nonce()
    
    # Compute MAC to prove we know PSK
    # This MAC says: "I know PSK, I received your nonce, here's mine"
    mac = compute_handshake_mac(psk, client_nonce, server_nonce)
    
    # Build response packet
    from core.protocol import build_handshake_response_packet
    response_packet = build_handshake_response_packet(server_nonce, mac)
    
    # Create state
    state = HandshakeState()
    state.state = HandshakeState.WAITING_CONFIRM
    state.client_nonce = client_nonce
    state.server_nonce = server_nonce
    # session_key not set yet (wait for client to confirm)
    
    return response_packet, state


def handshake_server_process_confirm(psk, state, confirm_packet):
    """
    SERVER STEP 2: Process client's confirmation.
    
    Verify client's MAC to complete handshake.
    
    Args:
        psk (bytes): Pre-shared key
        state (HandshakeState): State from process_init
        confirm_packet (bytes): Client's confirm packet
        
    Returns:
        HandshakeState: Updated state (CONFIRMED or FAILED)
        
    Design Critical:
        Final authentication step - if client's MAC is wrong,
        we REJECT the connection entirely.
    """
    # Validate state
    if state.state != HandshakeState.WAITING_CONFIRM:
        raise ValueError(f"Wrong state for processing confirm: {state.state}")
    
    # Parse confirm packet
    from core.protocol import parse_handshake_confirm_packet
    try:
        parsed = parse_handshake_confirm_packet(confirm_packet)
    except Exception as e:
        state.state = HandshakeState.FAILED
        return state
    
    client_mac = parsed['mac']
    
    # CRITICAL: Verify client's MAC
    # This proves client knows the PSK
    is_valid = verify_handshake_mac(
        psk,
        state.client_nonce,
        state.server_nonce,
        client_mac
    )
    
    if not is_valid:
        # Client doesn't know PSK - reject!
        state.state = HandshakeState.FAILED
        return state
    
    # Client is authentic! Derive session key
    session_key = derive_session_key(psk, state.client_nonce, state.server_nonce)
    state.session_key = session_key
    
    # Handshake complete
    state.state = HandshakeState.CONFIRMED
    
    return state