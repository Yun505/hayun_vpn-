"""
Protocol constants for MST VPN.

Defines packet formats, types, and sizes.
All multi-byte integers use big-endian (network byte order).
"""

# Protocol version
PROTOCOL_VERSION = 1  # Current version

# Packet types
PACKET_TYPE_HANDSHAKE_INIT = 0x01      # Client → Server: initiate handshake
PACKET_TYPE_HANDSHAKE_RESPONSE = 0x02  # Server → Client: respond with nonce + MAC
PACKET_TYPE_HANDSHAKE_CONFIRM = 0x03   # Client → Server: confirm with MAC
PACKET_TYPE_DATA = 0x04                 # Encrypted data packet

# Field sizes (in bytes)
VERSION_SIZE = 1       # Protocol version field
TYPE_SIZE = 1          # Packet type field
NONCE_SIZE = 24        # Nonce size (matches crypto.py)
MAC_SIZE = 32          # HMAC-SHA256 output
SEQUENCE_SIZE = 8      # 64-bit sequence number
AUTH_TAG_SIZE = 16     # Poly1305 auth tag

# Packet sizes (for validation)
HANDSHAKE_INIT_SIZE = VERSION_SIZE + TYPE_SIZE + NONCE_SIZE  # 26 bytes
HANDSHAKE_RESPONSE_SIZE = VERSION_SIZE + TYPE_SIZE + NONCE_SIZE + MAC_SIZE  # 58 bytes
HANDSHAKE_CONFIRM_SIZE = VERSION_SIZE + TYPE_SIZE + MAC_SIZE  # 34 bytes
DATA_HEADER_SIZE = VERSION_SIZE + TYPE_SIZE + SEQUENCE_SIZE  # 10 bytes

# Maximum packet size (prevent memory exhaustion attacks)
MAX_PACKET_SIZE = 65535  # 64 KB (typical UDP limit)
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - DATA_HEADER_SIZE - AUTH_TAG_SIZE

# Magic bytes for packet identification (optional, for future use)
MAGIC_BYTES = b'MST1'  # "MST" + version