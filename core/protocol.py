"""
Protocol layer for MST VPN.

Handles packet serialization (Python → bytes) and 
deserialization (bytes → Python) for all packet types.

Packet formats:
- Handshake Init: version + type + client_nonce
- Handshake Response: version + type + server_nonce + mac
- Handshake Confirm: version + type + mac
- Data: version + type + sequence_number + ciphertext + auth_tag
"""

import struct
from core.constants import *

class PacketError(Exception):
    """Raised when packet parsing or validation fails."""
    pass
def build_handshake_init_packet(client_nonce):
    """
    Build a handshake initiation packet.
    
    Client sends this first to start the handshake.
    
    Format:
    ┌──────────┬─────────┬──────────────────┐
    │ Version  │  Type   │  Client Nonce    │
    │ (1 byte) │ (1 byte)│   (24 bytes)     │
    └──────────┴─────────┴──────────────────┘
    
    Args:
        client_nonce (bytes): 24-byte random nonce
        
    Returns:
        bytes: Serialized packet (26 bytes)
        
    Raises:
        ValueError: If nonce has wrong length
    """
    if len(client_nonce) != NONCE_SIZE:
        raise ValueError(f"Client nonce must be {NONCE_SIZE} bytes")
    
    # Pack: version (1 byte) + type (1 byte) + nonce (24 bytes)
    # 'B' = unsigned char (1 byte)
    # 'B' = unsigned char (1 byte)
    # '24s' = 24-byte string
    packet = struct.pack(
        '!BB24s',  # '!' means big-endian (network byte order)
        PROTOCOL_VERSION,
        PACKET_TYPE_HANDSHAKE_INIT,
        client_nonce
    )
    
    return packet


def parse_handshake_init_packet(packet_bytes):
    """
    Parse a handshake initiation packet.
    
    Server receives this from client.
    
    Args:
        packet_bytes (bytes): Raw packet data
        
    Returns:
        dict: {'version': int, 'type': int, 'client_nonce': bytes}
        
    Raises:
        PacketError: If packet is malformed or has wrong size
    """
    # Validate size first
    if len(packet_bytes) != HANDSHAKE_INIT_SIZE:
        raise PacketError(
            f"Handshake init packet must be {HANDSHAKE_INIT_SIZE} bytes, "
            f"got {len(packet_bytes)}"
        )
    
    # Unpack the packet
    try:
        version, packet_type, client_nonce = struct.unpack('!BB24s', packet_bytes)
    except struct.error as e:
        raise PacketError(f"Failed to parse packet: {e}")
    
    # Validate version
    if version != PROTOCOL_VERSION:
        raise PacketError(
            f"Unsupported protocol version: {version} "
            f"(expected {PROTOCOL_VERSION})"
        )
    
    # Validate type
    if packet_type != PACKET_TYPE_HANDSHAKE_INIT:
        raise PacketError(
            f"Wrong packet type: {packet_type} "
            f"(expected {PACKET_TYPE_HANDSHAKE_INIT})"
        )
    
    return {
        'version': version,
        'type': packet_type,
        'client_nonce': client_nonce
    }

def build_handshake_response_packet(server_nonce, mac):
    """
    Build a handshake response packet.
    
    Server sends this in response to client's init.
    Includes server's nonce and MAC proving it knows the PSK.
    
    Format:
    ┌──────────┬─────────┬──────────────────┬──────────────────┐
    │ Version  │  Type   │  Server Nonce    │       MAC        │
    │ (1 byte) │ (1 byte)│   (24 bytes)     │   (32 bytes)     │
    └──────────┴─────────┴──────────────────┴──────────────────┘
    
    Args:
        server_nonce (bytes): 24-byte random nonce
        mac (bytes): 32-byte HMAC-SHA256
        
    Returns:
        bytes: Serialized packet (58 bytes)
    """
    if len(server_nonce) != NONCE_SIZE:
        raise ValueError(f"Server nonce must be {NONCE_SIZE} bytes")
    if len(mac) != MAC_SIZE:
        raise ValueError(f"MAC must be {MAC_SIZE} bytes")
    
    packet = struct.pack(
        '!BB24s32s',
        PROTOCOL_VERSION,
        PACKET_TYPE_HANDSHAKE_RESPONSE,
        server_nonce,
        mac
    )
    
    return packet

def parse_handshake_response_packet(packet_bytes):
    """
    Parse a handshake response packet.
    
    Client receives this from server.
    
    Args:
        packet_bytes (bytes): Raw packet data
        
    Returns:
        dict: {'version', 'type', 'server_nonce', 'mac'}
        
    Raises:
        PacketError: If packet is malformed
    """
    if len(packet_bytes) != HANDSHAKE_RESPONSE_SIZE:
        raise PacketError(
            f"Handshake response packet must be {HANDSHAKE_RESPONSE_SIZE} bytes, "
            f"got {len(packet_bytes)}"
        )
    
    try:
        version, packet_type, server_nonce, mac = struct.unpack(
            '!BB24s32s',
            packet_bytes
        )
    except struct.error as e:
        raise PacketError(f"Failed to parse packet: {e}")
    
    if version != PROTOCOL_VERSION:
        raise PacketError(f"Unsupported protocol version: {version}")
    
    if packet_type != PACKET_TYPE_HANDSHAKE_RESPONSE:
        raise PacketError(f"Wrong packet type: {packet_type}")
    
    return {
        'version': version,
        'type': packet_type,
        'server_nonce': server_nonce,
        'mac': mac
    }

def build_data_packet(sequence_number, ciphertext):
    """
    Build a data packet with encrypted payload.
    
    Format:
    ┌──────────┬─────────┬──────────────┬─────────────┬──────────────┐
    │ Version  │  Type   │  Sequence #  │ Ciphertext  │  Auth Tag    │
    │ (1 byte) │ (1 byte)│  (8 bytes)   │ (N bytes)   │  (16 bytes)  │
    └──────────┴─────────┴──────────────┴─────────────┴──────────────┘
    
    Args:
        sequence_number (int): 64-bit sequence number (0 to 2^64-1)
        ciphertext (bytes): Encrypted payload with auth tag
        
    Returns:
        bytes: Serialized packet
        
    Raises:
        ValueError: If sequence number out of range or ciphertext too large
    """
    # Validate sequence number
    if not (0 <= sequence_number < 2**64):
        raise ValueError(f"Sequence number must be 0-{2**64-1}")
    
    # Validate ciphertext size
    if len(ciphertext) > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Ciphertext too large: {len(ciphertext)} bytes "
            f"(max {MAX_PAYLOAD_SIZE})"
        )
    
    # Build header: version + type + sequence
    # 'Q' = unsigned long long (8 bytes, 64-bit)
    header = struct.pack(
        '!BBQ',
        PROTOCOL_VERSION,
        PACKET_TYPE_DATA,
        sequence_number
    )
    
    # Append ciphertext (already includes auth tag from encrypt_data)
    packet = header + ciphertext
    
    return packet


def parse_data_packet(packet_bytes):
    """
    Parse a data packet.
    
    Args:
        packet_bytes (bytes): Raw packet data
        
    Returns:
        dict: {
            'version': int,
            'type': int,
            'sequence_number': int,
            'ciphertext': bytes  # Includes auth tag
        }
        
    Raises:
        PacketError: If packet is malformed or too small
    """
    # Minimum size: header (10 bytes) + auth tag (16 bytes)
    min_size = DATA_HEADER_SIZE + AUTH_TAG_SIZE
    
    if len(packet_bytes) < min_size:
        raise PacketError(
            f"Data packet too small: {len(packet_bytes)} bytes "
            f"(minimum {min_size})"
        )
    
    # Check maximum size
    if len(packet_bytes) > MAX_PACKET_SIZE:
        raise PacketError(
            f"Data packet too large: {len(packet_bytes)} bytes "
            f"(max {MAX_PACKET_SIZE})"
        )
    
    # Parse header
    try:
        version, packet_type, sequence_number = struct.unpack(
            '!BBQ',
            packet_bytes[:DATA_HEADER_SIZE]
        )
    except struct.error as e:
        raise PacketError(f"Failed to parse header: {e}")
    
    # Validate version and type
    if version != PROTOCOL_VERSION:
        raise PacketError(f"Unsupported protocol version: {version}")
    
    if packet_type != PACKET_TYPE_DATA:
        raise PacketError(f"Wrong packet type: {packet_type}")
    
    # Extract ciphertext (everything after header)
    ciphertext = packet_bytes[DATA_HEADER_SIZE:]
    
    return {
        'version': version,
        'type': packet_type,
        'sequence_number': sequence_number,
        'ciphertext': ciphertext
    }

def build_handshake_confirm_packet(mac):
    """
        Build a handshake confirmation packet.
        Client sends this as the third message to prove it knows PSK.
        Format:
        ┌──────────┬─────────┬──────────────────┐
        │ Version  │  Type   │       MAC        │
        │ (1 byte) │ (1 byte)│   (32 bytes)     │
        └──────────┴─────────┴──────────────────┘
    Args:
            mac (bytes): 32-byte HMAC-SHA256
        Returns:
            bytes: Serialized packet (34 bytes)
        Design Note:
    Why separate packet type for confirm?
            - Distinguishes from server's response (different direction)
            - 
    Allows different handling logic
            - Future-proof (could add extra fields later)
        """
    if len(mac) != MAC_SIZE:
        raise ValueError(f"MAC must be {MAC_SIZE} bytes")
    
    packet = struct.pack(
        '!BB32s',
        PROTOCOL_VERSION,
        PACKET_TYPE_HANDSHAKE_CONFIRM,
        mac
    )
    
    return packet

def parse_handshake_confirm_packet(packet_bytes):
    """
    Parse a handshake confirmation packet.
    
    Server receives this from client to complete handshake.
    
    Args:
        packet_bytes (bytes): Raw packet data
        
    Returns:
        dict: {'version', 'type', 'mac'}
        
    Raises:
        PacketError: If packet is malformed
    """
    if len(packet_bytes) != HANDSHAKE_CONFIRM_SIZE:
        raise PacketError(
            f"Handshake confirm packet must be {HANDSHAKE_CONFIRM_SIZE} bytes, "
            f"got {len(packet_bytes)}"
        )
    
    try:
        version, packet_type, mac = struct.unpack('!BB32s', packet_bytes)
    except struct.error as e:
        raise PacketError(f"Failed to parse packet: {e}")
    
    if version != PROTOCOL_VERSION:
        raise PacketError(f"Unsupported protocol version: {version}")
    
    if packet_type != PACKET_TYPE_HANDSHAKE_CONFIRM:
        raise PacketError(f"Wrong packet type: {packet_type}")
    
    return {
        'version': version,
        'type': packet_type,
        'mac': mac
    }

