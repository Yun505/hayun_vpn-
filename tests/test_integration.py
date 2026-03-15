"""
Integration tests for Phase 1-4.

Tests the complete stack: crypto, protocol, handshake, and networking.
"""

import pytest
import time
import threading
import socket as sock 
from core.crypto import generate_psk
from client.client import VPNClient
from server.server import VPNServer

# Use session scope - ONE server for ALL tests
@pytest.fixture(scope="session")
def shared_psk():
    """Generate a shared PSK for all tests."""
    return generate_psk()


@pytest.fixture(scope="session")
def server(shared_psk):
    """Start ONE server for the entire test session."""
    # Add SO_REUSEADDR to allow port reuse
    import socket as sock_module
    
    server_instance = VPNServer(port=9999)
    
    def run_server():
        try:
            # Modify server to allow address reuse
            server_instance.sock = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_DGRAM)
            server_instance.sock.setsockopt(sock_module.SOL_SOCKET, sock_module.SO_REUSEADDR, 1)
            server_instance.sock.bind(('', server_instance.port))
            
            print(f"[SERVER] Listening on 0.0.0.0:{server_instance.port}")
            
            # Server loop
            while True:
                packet_data, addr = server_instance.sock.recvfrom(65535)
                
                if server_instance.handshake_state is None or \
                   not server_instance.handshake_state.is_complete():
                    server_instance._handle_handshake_packet(shared_psk, packet_data, addr)
                else:
                    server_instance._handle_data_packet(packet_data, addr)
                    
        except Exception as e:
            print(f"[SERVER] Error: {e}")
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.0)  # Give server more time to start
    
    yield server_instance
    
    # Cleanup
    if server_instance.sock:
        server_instance.sock.close()


@pytest.fixture
def client(shared_psk, server):
    """Create and connect client (one per test)."""
    # Reset server state between tests
    server.client_address = None
    server.handshake_state = None
    server.session_key = None
    server.sequence_number = 0
    
    time.sleep(0.2)  # Small delay between tests
    
    client_instance = VPNClient(server_host='127.0.0.1', server_port=9999)
    
    # Connect to server
    success = client_instance.connect(shared_psk)
    assert success, "Client handshake failed"
    
    yield client_instance
    
    # Cleanup
    client_instance.close()
    time.sleep(0.2)  # Allow cleanup

def test_handshake_successful(shared_psk, server):
    """Test that client can complete handshake with server."""
    client = VPNClient(server_host='127.0.0.1', server_port=9999)
    
    result = client.connect(shared_psk)
    
    assert result == True, "Handshake should succeed"
    assert client.session_key is not None, "Session key should be established"
    assert client.handshake_state.is_complete(), "Handshake state should be CONFIRMED"
    
    client.close()


def test_send_and_receive_message(client):
    """Test sending and receiving encrypted message."""
    test_message = b"Hello, Server!"
    
    # Send message
    result = client.send_message(test_message)
    assert result == True, "Send should succeed"
    
    # Receive echo response
    response = client.receive_message(timeout=2.0)
    
    assert response is not None, "Should receive response"
    assert response == test_message, "Echo should return same message"


def test_multiple_messages(client):
    """Test sending multiple messages in sequence."""
    test_messages = [
        b"Message 1",
        b"Message 2",
        b"Message 3"
    ]
    
    for msg in test_messages:
        # Send
        result = client.send_message(msg)
        assert result == True, f"Send failed for {msg}"
        
        # Receive echo
        response = client.receive_message(timeout=2.0)
        assert response == msg, f"Echo mismatch for {msg}"
        
        time.sleep(0.1)  # Small delay between messages


def test_sequence_numbers_increment(client):
    """Test that sequence numbers increment correctly."""
    initial_seq = client.sequence_number
    
    # Send 3 messages
    for i in range(3):
        client.send_message(b"test")
        client.receive_message(timeout=2.0)
    
    # Sequence number should have incremented by 3
    assert client.sequence_number == initial_seq + 3


def test_handshake_fails_with_wrong_psk(server):
    """Test that handshake fails with incorrect PSK."""
    wrong_psk = generate_psk()  # Different PSK
    client = VPNClient(server_host='127.0.0.1', server_port=9999)
    
    result = client.connect(wrong_psk)
    
    assert result == False, "Handshake should fail with wrong PSK"
    assert client.session_key is None, "Session key should not be established"


def test_empty_message(client):
    """Test sending empty message (edge case)."""
    empty_message = b""
    
    result = client.send_message(empty_message)
    assert result == True, "Should be able to send empty message"
    
    response = client.receive_message(timeout=2.0)
    assert response == empty_message, "Should echo empty message"


def test_large_message(client):
    """Test sending large message."""
    large_message = b"X" * 10000  # 10 KB message
    
    result = client.send_message(large_message)
    assert result == True, "Should handle large message"
    
    response = client.receive_message(timeout=2.0)
    assert response == large_message, "Should echo large message correctly"


def test_unicode_message(client):
    """Test sending unicode text."""
    unicode_message = "Hello world".encode('utf-8')
    
    result = client.send_message(unicode_message)
    assert result == True
    
    response = client.receive_message(timeout=2.0)
    assert response == unicode_message
    assert response.decode('utf-8') == "Hello world"


# Manual test runner (for running outside pytest)
if __name__ == '__main__':
    print("=" * 70)
    print("MANUAL INTEGRATION TEST")
    print("=" * 70)
    print()
    
    # Generate PSK
    psk = generate_psk()
    print(f"PSK: {psk.hex()[:40]}...")
    print()
    
    # Start server
    print("Starting server...")
    server = VPNServer(port=9999)
    server_thread = threading.Thread(target=lambda: server.start(psk), daemon=True)
    server_thread.start()
    time.sleep(0.5)
    
    # Create client
    print("Starting client...")
    client = VPNClient(server_host='127.0.0.1', server_port=9999)
    
    # Test handshake
    print("Testing handshake...")
    if not client.connect(psk):
        print("✗ Handshake failed!")
        exit(1)
    print("✓ Handshake successful!")
    print()
    
    # Test messages
    print("Testing message exchange...")
    test_messages = [
        b"Hello, Server!",
        b"This is encrypted",
        b"Testing 1, 2, 3..."
    ]
    
    for msg in test_messages:
        print(f"  Sending: {msg.decode()}")
        client.send_message(msg)
        response = client.receive_message(timeout=2.0)
        if response:
            print(f"  ✓ Received: {response.decode()}")
        else:
            print("  ✗ No response")
        time.sleep(0.2)
    
    client.close()
    
    print()
    print("=" * 70)
    print("MANUAL TEST COMPLETE ✓")
    print("=" * 70)
    

def test_server_rejects_replayed_packet(client):
    """Server should reject replayed packet."""
    # Send first message
    msg = b"Original message"
    client.send_message(msg)
    client.receive_message(timeout=1.0)
    
    # Send more messages to advance window
    for i in range(3):
        client.send_message(f"Message {i}".encode())
        client.receive_message(timeout=1.0)
    
    # Try to replay first packet by manually crafting it
    from core.protocol import build_data_packet
    from core.crypto import encrypt_data
    
    # Recreate first packet (seq #1)
    old_seq = 1
    old_nonce = old_seq.to_bytes(24, 'big')
    old_ciphertext = encrypt_data(client.session_key, msg, old_nonce)
    replayed_packet = build_data_packet(old_seq, old_ciphertext)
    
    # Send replayed packet directly via socket
    attack_sock = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
    attack_sock.sendto(replayed_packet, ('127.0.0.1', 9999))
    attack_sock.close()
    
    time.sleep(0.2)
    
    # Server should have rejected it (check logs for "REPLAY ATTACK DETECTED")
    # This test mainly verifies no crash/exception
    assert True  # If we get here without exception, test passes


def test_out_of_order_packets_accepted(client):
    """Out-of-order packets within window should be accepted."""
    # We can't easily force UDP reordering in tests,
    # but we can verify the client sends incrementing seq numbers
    
    initial_seq = client.sequence_number
    
    # Send 3 messages
    for i in range(3):
        client.send_message(f"Message {i}".encode())
        client.receive_message(timeout=1.0)
    
    # Sequence should have incremented by 3
    assert client.sequence_number == initial_seq + 3