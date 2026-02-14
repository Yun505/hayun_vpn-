"""Tests for handshake protocol."""
import pytest

from core.crypto import (
    generate_psk,
    handshake_client_init,
    handshake_client_process_response,
    handshake_server_process_init,
    handshake_server_process_confirm,
    HandshakeState
)
def test_full_handshake_success():
    """Complete handshake should succeed with correct PSK."""
    psk = generate_psk()
    
    # CLIENT: Initiate handshake
    client_init_packet, client_state = handshake_client_init(psk)
    assert client_state.state == HandshakeState.WAITING_RESPONSE
    assert client_state.client_nonce is not None
    assert client_state.session_key is None  # Not derived yet
    
    # SERVER: Process init, send response
    server_response_packet, server_state = handshake_server_process_init(
        psk,
        client_init_packet
    )
    assert server_state.state == HandshakeState.WAITING_CONFIRM
    assert server_state.server_nonce is not None
    assert server_state.session_key is None  # Not derived yet
    # CLIENT: Process response, send confirm
    
    client_confirm_packet, client_state = handshake_client_process_response(
        psk,
        client_state,
        server_response_packet
    )
    assert client_state.state == HandshakeState.CONFIRMED
    assert client_state.session_key is not None  # Now derived!
    
    # SERVER: Process confirm, complete handshake
    server_state = handshake_server_process_confirm(
        psk,
        server_state,
        client_confirm_packet
    )
    
    assert server_state.state == HandshakeState.CONFIRMED
    assert server_state.session_key is not None
    
    # CRITICAL: Both sides should have SAME session key
    assert client_state.session_key == server_state.session_key

def test_handshake_fails_with_wrong_psk():
    """Handshake should fail if PSKs don't match."""
    client_psk = generate_psk()
    server_psk = generate_psk()  # Different PSK!
    
    # Client init
    client_init_packet, client_state = handshake_client_init(client_psk)
    
    # Server processes with different PSK
    server_response_packet, server_state = handshake_server_process_init(
        server_psk,  # Wrong PSK
        client_init_packet
    )
    
    # Client tries to process response
    # MAC won't match because PSKs are different
    client_confirm_packet, client_state = handshake_client_process_response(
        client_psk,
        client_state,
        server_response_packet
    )

    # Handshake should fail
    assert client_state.state == HandshakeState.FAILED
    assert client_confirm_packet is None  # No confirm sent 
    
def test_handshake_server_rejects_wrong_client_mac():
    """Server should reject client with wrong MAC."""
    psk = generate_psk()
    # Normal handshake up to client confirm
    client_init_packet, client_state = handshake_client_init(psk)

    server_response_packet, server_state = handshake_server_process_init(
        psk,
        client_init_packet
    )
    client_confirm_packet, client_state = handshake_client_process_response(
        psk,
        client_state,
        server_response_packet
    )
    
    # Tamper with client's confirm MAC
    from core.protocol import build_handshake_confirm_packet
    fake_mac = b'\x00' * 32
    tampered_confirm = build_handshake_confirm_packet(fake_mac)
    
    # Server processes tampered confirm
    server_state = handshake_server_process_confirm(
        psk,
        server_state,
        tampered_confirm
    )
    
    # Should fail
    assert server_state.state == HandshakeState.FAILED

def test_handshake_rejects_malformed_packets():
    """Handshake should gracefully handle garbage packets."""
    psk = generate_psk()
    client_init_packet, client_state = handshake_client_init(psk)

    # Send garbage as server response
    garbage = b'this is not a valid packet'
    client_confirm_packet, client_state = handshake_client_process_response(
        psk,
        client_state,
        garbage
    )

    assert client_state.state == HandshakeState.FAILED
    assert client_confirm_packet is None
    
def test_handshake_state_prevents_wrong_order():
    """Can't process messages in wrong order."""
    psk = generate_psk()
    
    client_init_packet, client_state = handshake_client_init(psk)
    server_response_packet, server_state = handshake_server_process_init(
        psk,
        client_init_packet
    )
    
    # Try to process confirm before processing response (wrong order)
    # Client state is still WAITING_RESPONSE
    from core.protocol import build_handshake_confirm_packet
    fake_confirm = build_handshake_confirm_packet(b'\x00' * 32)
    
    # This should raise ValueError (wrong state)
    with pytest.raises(ValueError):
        handshake_server_process_confirm(psk, client_state, fake_confirm)
        
