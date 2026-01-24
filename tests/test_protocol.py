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