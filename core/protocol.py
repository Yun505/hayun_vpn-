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
