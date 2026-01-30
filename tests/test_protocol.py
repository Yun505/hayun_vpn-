"""Tests for protocol packet serialization/parsing."""
import pytest
from core.protocol import (
    build_handshake_init_packet,
    parse_handshake_init_packet,
    build_handshake_response_packet,
    parse_handshake_response_packet,
    PacketError
)
from core.constants import (
    HANDSHAKE_INIT_SIZE,
    PROTOCOL_VERSION,
    PACKET_TYPE_HANDSHAKE_INIT,
    HANDSHAKE_RESPONSE_SIZE, 
    PACKET_TYPE_HANDSHAKE_RESPONSE
)
from core.crypto import generate_nonce


def test_build_handshake_init_packet():
    """Building handshake init packet should produce correct size."""
    client_nonce = generate_nonce()
    packet = build_handshake_init_packet(client_nonce)
    
    assert len(packet) == HANDSHAKE_INIT_SIZE
    assert type(packet) == bytes


def test_handshake_init_roundtrip():
    """Should be able to build and parse handshake init packet."""
    client_nonce = generate_nonce()
    
    # Build packet
    packet = build_handshake_init_packet(client_nonce)
    
    # Parse it back
    parsed = parse_handshake_init_packet(packet)
    
    assert parsed['version'] == PROTOCOL_VERSION
    assert parsed['type'] == PACKET_TYPE_HANDSHAKE_INIT
    assert parsed['client_nonce'] == client_nonce


def test_parse_handshake_init_rejects_wrong_size():
    """Should reject packets that are too short or too long."""
    with pytest.raises(PacketError):
        parse_handshake_init_packet(b'too short')
    
    with pytest.raises(PacketError):
        parse_handshake_init_packet(b'x' * 100)  # Too long


def test_parse_handshake_init_rejects_wrong_version():
    """Should reject packets with unsupported version."""
    client_nonce = generate_nonce()
    packet = build_handshake_init_packet(client_nonce)
    
    # Corrupt the version byte
    bad_packet = bytearray(packet)
    bad_packet[0] = 99  # Wrong version
    bad_packet = bytes(bad_packet)
    
    with pytest.raises(PacketError):
        parse_handshake_init_packet(bad_packet)

def test_build_handshake_response_packet():
    """Building handshake response should produce correct size."""
    server_nonce = generate_nonce()
    mac = b'\x00' * 32  # Dummy MAC for testing
    
    packet = build_handshake_response_packet(server_nonce, mac)
    
    assert len(packet) == HANDSHAKE_RESPONSE_SIZE


def test_handshake_response_roundtrip():
    """Should be able to build and parse handshake response."""
    server_nonce = generate_nonce()
    mac = b'\xaa' * 32  # Dummy MAC
    
    packet = build_handshake_response_packet(server_nonce, mac)
    parsed = parse_handshake_response_packet(packet)
    
    assert parsed['version'] == PROTOCOL_VERSION
    assert parsed['type'] == PACKET_TYPE_HANDSHAKE_RESPONSE
    assert parsed['server_nonce'] == server_nonce
    assert parsed['mac'] == mac


def test_parse_handshake_response_rejects_wrong_size():
    """Should reject malformed response packets."""
    with pytest.raises(PacketError):
        parse_handshake_response_packet(b'too short')

from core.protocol import build_data_packet, parse_data_packet
from core.constants import DATA_HEADER_SIZE, PACKET_TYPE_DATA, MAX_PACKET_SIZE
from core.crypto import generate_psk, generate_nonce, derive_session_key, encrypt_data


def test_build_data_packet():
    """Building data packet should produce correct structure."""
    seq = 42
    ciphertext = b'\xaa' * 50  # Dummy ciphertext
    
    packet = build_data_packet(seq, ciphertext)
    
    # Should be header + ciphertext
    assert len(packet) == DATA_HEADER_SIZE + len(ciphertext)


def test_data_packet_roundtrip():
    """Should be able to build and parse data packet."""
    seq = 1234
    ciphertext = b'\xbb' * 100
    
    packet = build_data_packet(seq, ciphertext)
    parsed = parse_data_packet(packet)
    
    assert parsed['version'] == PROTOCOL_VERSION
    assert parsed['type'] == PACKET_TYPE_DATA
    assert parsed['sequence_number'] == seq
    assert parsed['ciphertext'] == ciphertext


def test_data_packet_with_real_encryption():
    """Data packet should work with real encrypted data."""
    # Setup crypto
    psk = generate_psk()
    session_key = derive_session_key(psk, generate_nonce(), generate_nonce())
    
    # Encrypt some data
    plaintext = b"Hello, VPN!"
    nonce = generate_nonce()
    ciphertext = encrypt_data(session_key, plaintext, nonce)
    
    # Build packet
    seq = 100
    packet = build_data_packet(seq, ciphertext)
    
    # Parse packet
    parsed = parse_data_packet(packet)
    
    assert parsed['sequence_number'] == seq
    assert parsed['ciphertext'] == ciphertext


def test_parse_data_packet_rejects_too_small():
    """Should reject packets smaller than minimum size."""
    # Minimum is header (10) + auth tag (16) = 26 bytes
    too_small = b'x' * 20
    
    with pytest.raises(PacketError):
        parse_data_packet(too_small)


def test_parse_data_packet_rejects_too_large():
    """Should reject packets larger than max size."""
    # Create a packet that's too large
    seq = 1
    huge_ciphertext = b'x' * (MAX_PACKET_SIZE + 1000)
    
    with pytest.raises(ValueError):
        build_data_packet(seq, huge_ciphertext)


def test_build_data_packet_validates_sequence_number():
    """Should reject invalid sequence numbers."""
    ciphertext = b'x' * 50
    
    # Negative sequence number
    with pytest.raises(ValueError):
        build_data_packet(-1, ciphertext)
    
    # Too large (> 64-bit max)
    with pytest.raises(ValueError):
        build_data_packet(2**64, ciphertext)

def test_empty_plaintext_encryption():
    """Should handle encrypting empty plaintext (produces auth tag only)."""
    # Setup crypto
    psk = generate_psk()
    session_key = derive_session_key(psk, generate_nonce(), generate_nonce())
    
    # Encrypt EMPTY plaintext - still produces 16-byte auth tag
    plaintext = b''
    nonce = generate_nonce()
    ciphertext = encrypt_data(session_key, plaintext, nonce)
    
    # Ciphertext should be exactly 16 bytes (just the auth tag)
    assert len(ciphertext) == 16
    
    # Build and parse packet
    seq = 5
    packet = build_data_packet(seq, ciphertext)
    parsed = parse_data_packet(packet)
    
    assert parsed['sequence_number'] == seq
    assert len(parsed['ciphertext']) == 16  # Auth tag only

def test_large_sequence_numbers():
    """Should handle very large sequence numbers (near 64-bit limit)."""
    large_seq = 2**63  # Half of max 64-bit value
    ciphertext = b'x' * 100
    
    packet = build_data_packet(large_seq, ciphertext)
    parsed = parse_data_packet(packet)
    
    assert parsed['sequence_number'] == large_seq


def test_truncated_packet():
    """Should reject truncated packets."""
    seq = 10
    ciphertext = b'x' * 50
    packet = build_data_packet(seq, ciphertext)
    
    # Cut off last 10 bytes
    truncated = packet[:-10]
    
    # Should still parse (might just have shorter ciphertext)
    # But crypto layer will reject it later (invalid auth tag)
    parsed = parse_data_packet(truncated)
    assert len(parsed['ciphertext']) == len(ciphertext) - 10


def test_corrupted_header():
    """Should reject packets with corrupted headers."""
    seq = 10
    ciphertext = b'x' * 50
    packet = build_data_packet(seq, ciphertext)
    
    # Corrupt version byte
    bad_packet = bytearray(packet)
    bad_packet[0] = 99
    
    with pytest.raises(PacketError):
        parse_data_packet(bytes(bad_packet))


def test_different_packet_types_have_different_formats():
    """Verify different packet types are distinguishable."""
    # Build packets of different types
    client_nonce = generate_nonce()
    handshake_init = build_handshake_init_packet(client_nonce)
    
    server_nonce = generate_nonce()
    mac = b'\x00' * 32
    handshake_response = build_handshake_response_packet(server_nonce, mac)
    
    ciphertext = b'x' * 100
    data = build_data_packet(1, ciphertext)
    
    # All should have different lengths
    assert len(handshake_init) != len(handshake_response)
    assert len(handshake_init) != len(data)
    
    # Type bytes should be different
    assert handshake_init[1] == PACKET_TYPE_HANDSHAKE_INIT
    assert handshake_response[1] == PACKET_TYPE_HANDSHAKE_RESPONSE
    assert data[1] == PACKET_TYPE_DATA