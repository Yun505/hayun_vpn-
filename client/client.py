"""
MST VPN Client

Connects to server, performs handshake, sends/receives encrypted data.
"""
from core.replay import SlidingWindow
import socket
import sys
import time
from core.crypto import (
    generate_psk,
    handshake_client_init,
    handshake_client_process_response,
    encrypt_data,
    decrypt_data,
    generate_nonce,
    HandshakeState
)
from core.protocol import (
    build_data_packet,
    parse_data_packet,
    PacketError
)

# Configuration constants
DEFAULT_SERVER_HOST = '127.0.0.1'  # localhost for testing
DEFAULT_SERVER_PORT = 9999
RECV_BUFFER_SIZE = 65535  # Maximum UDP packet size
HANDSHAKE_TIMEOUT = 5.0  # seconds to wait for handshake response


class VPNClient:
    """
    VPN Client for MST protocol.
    
    Design Pattern: Class-based
    
    Why a class?
    - Encapsulates socket and state
    - Easy to add methods (connect, send, receive)
    - Clean resource management (socket cleanup)
    
    Alternative: Functional approach
    - Socket passed between functions (error-prone)
    - State scattered across variables
    
    Class approach:
    - Socket lifecycle managed in one place
    - State bundled together
    - Can use __enter__/__exit__ for context manager
    """
    
    def __init__(self, server_host=DEFAULT_SERVER_HOST, 
                 server_port=DEFAULT_SERVER_PORT):
        """
        Initialize VPN client.
        
        Args:
            server_host (str): Server IP address
            server_port (int): Server port number
            
        Design Note:
            We don't create the socket here - we do it in connect().
            Why? Separation of concerns:
            - __init__ = configuration
            - connect() = actual network operation
        """
        self.server_host = server_host
        self.server_port = server_port
        self.server_address = (server_host, server_port)
        
        self.sock = None  # Created in connect()
        self.handshake_state = None  # Set during handshake
        self.session_key = None  # Set after successful handshake
        self.sequence_number = 0  # Incremented for each data packet
        self.replay_window = SlidingWindow(window_size=64) # For replay attack prevention 
        
        print(f"[CLIENT] Initialized. Server: {server_host}:{server_port}")
    
    def connect(self, psk):
        """
        Connect to server and perform handshake.
        
        Args:
            psk (bytes): Pre-shared key (32 bytes)
            
        Returns:
            bool: True if handshake successful, False otherwise
            
        Design Critical:
            This performs the THREE-WAY HANDSHAKE.
            If any step fails, we CLOSE the socket and return False.
        """
        print("[CLIENT] Creating UDP socket...")
        
        # Create UDP socket
        # AF_INET = IPv4, SOCK_DGRAM = UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Set socket timeout for handshake
        # Why? Prevent infinite blocking if server doesn't respond
        self.sock.settimeout(HANDSHAKE_TIMEOUT)
        
        print(f"[CLIENT] Starting handshake with {self.server_address}...")
        
        try:
            # STEP 1: Send handshake init
            init_packet, self.handshake_state = handshake_client_init(psk)
            print(f"[CLIENT] Sending handshake init ({len(init_packet)} bytes)...")
            self.sock.sendto(init_packet, self.server_address)
            
            # STEP 2: Receive server response
            print("[CLIENT] Waiting for server response...")
            response_data, addr = self.sock.recvfrom(RECV_BUFFER_SIZE)
            
            # Verify response came from expected server
            # Why? Prevent spoofed responses from other hosts
            if addr != self.server_address:
                print(f"[CLIENT] ERROR: Response from unexpected address: {addr}")
                self.sock.close()
                return False
            
            print(f"[CLIENT] Received response ({len(response_data)} bytes)")
            
            # STEP 3: Process response, send confirmation
            confirm_packet, self.handshake_state = \
                handshake_client_process_response(
                    psk,
                    self.handshake_state,
                    response_data
                )
            
            if not self.handshake_state.is_complete():
                print("[CLIENT] ERROR: Handshake failed (MAC verification failed)")
                self.sock.close()
                return False
            
            print(f"[CLIENT] Sending handshake confirm ({len(confirm_packet)} bytes)...")
            self.sock.sendto(confirm_packet, self.server_address)
            
            # Store session key
            self.session_key = self.handshake_state.session_key
            
            print("[CLIENT] ✓ Handshake complete! Session key established.")
            
            # Remove timeout for normal operation
            # Why? Data packets might be sent infrequently
            self.sock.settimeout(None)
            
            return True
            
        except socket.timeout:
            print("[CLIENT] ERROR: Handshake timeout - no response from server")
            self.sock.close()
            return False
            
        except Exception as e:
            print(f"[CLIENT] ERROR during handshake: {e}")
            if self.sock:
                self.sock.close()
            return False
    
    def send_message(self, plaintext):
        """
        Send an encrypted message to server.
        
        Args:
            plaintext (bytes): Message to send
            
        Returns:
            bool: True if sent successfully, False otherwise
            
        Design Note:
            Why increment sequence number BEFORE encrypting?
            - Sequence number is used as nonce
            - Ensures nonce is unique for each message
            - If we encrypted first, we'd need separate nonce tracking
        """
        if not self.session_key:
            print("[CLIENT] ERROR: No session key - handshake not complete")
            return False
        
        try:
            # Increment sequence number (used as nonce)
            self.sequence_number += 1
            
            # Create nonce from sequence number
            # Why 24 bytes? PyNaCl SecretBox requirement
            # Why big-endian? Network byte order standard
            nonce = self.sequence_number.to_bytes(24, 'big')
            
            print(f"[CLIENT] Encrypting message (seq #{self.sequence_number})...")
            
            # Encrypt plaintext
            ciphertext = encrypt_data(self.session_key, plaintext, nonce)
            
            # Build data packet
            packet = build_data_packet(self.sequence_number, ciphertext)
            
            print(f"[CLIENT] Sending packet ({len(packet)} bytes)...")
            
            # Send to server
            self.sock.sendto(packet, self.server_address)
            
            return True
            
        except Exception as e:
            print(f"[CLIENT] ERROR sending message: {e}")
            return False
    
    def receive_message(self, timeout=None):
        """
        Receive and decrypt a message from server.
        
        Args:
            timeout (float): Seconds to wait, None = block forever
            
        Returns:
            bytes: Decrypted plaintext, or None if error/timeout
            
        Design Critical:
            Always verify packets BEFORE decrypting.
            Never trust network data!
        """
        if not self.session_key:
            print("[CLIENT] ERROR: No session key - handshake not complete")
            return None
        
        try:
            # Set timeout if specified
            old_timeout = self.sock.gettimeout()
            if timeout is not None:
                self.sock.settimeout(timeout)
            
            print("[CLIENT] Waiting for message...")
            
            # Receive packet
            packet_data, addr = self.sock.recvfrom(RECV_BUFFER_SIZE)
            
            # Restore original timeout
            self.sock.settimeout(old_timeout)
            
            # Verify sender
            if addr != self.server_address:
                print(f"[CLIENT] WARNING: Packet from unexpected address: {addr}")
                return None
            
            print(f"[CLIENT] Received packet ({len(packet_data)} bytes)")
            
            # Parse packet
            parsed = parse_data_packet(packet_data)
            sequence_number = parsed['sequence_number']
            ciphertext = parsed['ciphertext']
            
            print(f"[CLIENT] Packet seq #{sequence_number}")
            
            # REPLAY PROTECTION
            if not self.replay_window.should_accept(sequence_number):
                print(f"[CLIENT] WARNING: Replay detected from server! Seq #{sequence_number}")
                return None
            
            # Create nonce from sequence number
            nonce = sequence_number.to_bytes(24, 'big')
            
            # Decrypt
            plaintext = decrypt_data(self.session_key, ciphertext, nonce)
            
            # Mark as received AFTER successful decryption
            self.replay_window.mark_received(sequence_number)
            
            print(f"[CLIENT] ✓ Message decrypted ({len(plaintext)} bytes)")
            
            return plaintext
            
        except socket.timeout:
            print("[CLIENT] Timeout waiting for message")
            return None
            
        except PacketError as e:
            print(f"[CLIENT] ERROR: Malformed packet - {e}")
            return None
            
        except Exception as e:
            print(f"[CLIENT] ERROR receiving message: {e}")
            return None
    
    def close(self):
        """
        Close connection and cleanup.
        
        Design Note:
            Always close sockets explicitly!
            OS has limited socket resources.
        """
        if self.sock:
            print("[CLIENT] Closing connection...")
            self.sock.close()
            self.sock = None


def main():
    """
    Main client program.
    
    Design: Interactive mode for testing.
    User can type messages to send to server.
    """
    print("=" * 60)
    print("MST VPN CLIENT")
    print("=" * 60)
    print()
    
    # For testing, use a hardcoded PSK
    # In production, load from file
    # TODO: Add command-line arg for PSK file
    print("[CLIENT] Generating PSK for testing...")
    psk = generate_psk()
    print(f"[CLIENT] PSK: {psk.hex()[:40]}...")
    print()
    print("[CLIENT] NOTE: Server must use same PSK!")
    print("[CLIENT] In production, share PSK securely out-of-band.")
    print()
    
    # Create client
    client = VPNClient()
    
    # Connect and handshake
    if not client.connect(psk):
        print("[CLIENT] Failed to connect. Exiting.")
        return
    
    print()
    print("[CLIENT] Connected! Type messages to send (Ctrl+C to quit)")
    print("-" * 60)
    
    try:
        while True:
            # Get user input
            message = input("Message: ")
            
            if not message:
                continue
            
            # Send message
            client.send_message(message.encode('utf-8'))
            
            # Wait for response
            response = client.receive_message(timeout=5.0)
            
            if response:
                print(f"Server response: {response.decode('utf-8')}")
            else:
                print("(No response from server)")
            
            print()
    
    except KeyboardInterrupt:
        print("\n[CLIENT] Shutting down...")
    
    finally:
        client.close()
        print("[CLIENT] Goodbye!")


if __name__ == '__main__':
    main()