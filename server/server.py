"""
MST VPN Server

Listens for client connections, performs handshake, echoes messages back.
"""

import socket
import sys
from core.crypto import (
    generate_psk,
    handshake_server_process_init,
    handshake_server_process_confirm,
    encrypt_data,
    decrypt_data,
    HandshakeState
)
from core.protocol import (
    build_data_packet,
    parse_data_packet,
    parse_handshake_init_packet,
    PacketError
)

# Configuration
DEFAULT_PORT = 9999
RECV_BUFFER_SIZE = 65535


class VPNServer:
    """
    VPN Server for MST protocol.
    
    Design: Single-client server (for Phase 4 simplicity).
    
    Limitations:
    - Only handles one client at a time
    - New client connection overwrites previous
    - No concurrent connections
    
    Future: Phase 7/8 could add multi-client support
    """
    
    def __init__(self, port=DEFAULT_PORT):
        """
        Initialize VPN server.
        
        Args:
            port (int): Port to listen on
        """
        self.port = port
        self.sock = None
        
        # Client state (None until client connects)
        self.client_address = None
        self.handshake_state = None
        self.session_key = None
        self.sequence_number = 0
        
        print(f"[SERVER] Initialized on port {port}")
    
    def start(self, psk):
        """
        Start server and listen for connections.
        
        Args:
            psk (bytes): Pre-shared key
            
        Design Note:
            Server never "connects" - it just binds to a port
            and waits for packets.
        """
        print("[SERVER] Creating UDP socket...")
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to port
        # '' means listen on all network interfaces
        # Why? So we can connect from other machines if needed
        self.sock.bind(('', self.port))
        
        print(f"[SERVER] Listening on 0.0.0.0:{self.port}")
        print("[SERVER] Waiting for client...")
        print()
        
        try:
            # Main server loop
            while True:
                # Receive packet
                packet_data, addr = self.sock.recvfrom(RECV_BUFFER_SIZE)
                
                # Handle packet based on current state
                if self.handshake_state is None or \
                   not self.handshake_state.is_complete():
                    # Still in handshake phase
                    self._handle_handshake_packet(psk, packet_data, addr)
                else:
                    # Handshake complete, handle data packet
                    self._handle_data_packet(packet_data, addr)
        
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        
        finally:
            if self.sock:
                self.sock.close()
            print("[SERVER] Goodbye!")
    
    def _handle_handshake_packet(self, psk, packet_data, addr):
        """
        Handle handshake packets from client.
        
        Args:
            psk (bytes): Pre-shared key
            packet_data (bytes): Received packet
            addr (tuple): Client address (IP, port)
            
        Design:
            Two-step handshake from server perspective:
            1. Receive init → send response
            2. Receive confirm → complete handshake
        """
        # Determine handshake step
        if self.handshake_state is None:
            # STEP 1: Client init
            self._handle_handshake_init(psk, packet_data, addr)
        
        elif self.handshake_state.state == HandshakeState.WAITING_CONFIRM:
            # STEP 2: Client confirm
            self._handle_handshake_confirm(psk, packet_data, addr)
        
        else:
            print(f"[SERVER] WARNING: Unexpected handshake packet in state "
                  f"{self.handshake_state.state}")
    
    def _handle_handshake_init(self, psk, packet_data, addr):
        """
        Handle client's handshake init (step 1).
        
        Design Critical:
            This is where we learn the client's address.
            All future communication is with this address.
        """
        print(f"[SERVER] Received handshake init from {addr}")
        
        # Set client address
        # Why? So we know where to send response
        self.client_address = addr
        
        # Process init packet
        response_packet, self.handshake_state = \
            handshake_server_process_init(psk, packet_data)
        
        if response_packet is None:
            print("[SERVER] ERROR: Failed to process handshake init")
            self.client_address = None
            return
        
        print(f"[SERVER] Sending handshake response to {addr} "
              f"({len(response_packet)} bytes)")
        
        # Send response
        self.sock.sendto(response_packet, addr)
        
        print("[SERVER] Waiting for client confirmation...")
    
    def _handle_handshake_confirm(self, psk, packet_data, addr):
        """
        Handle client's handshake confirm (step 2).
        
        Design Critical:
            Final authentication - if MAC fails, REJECT client.
        """
        # Verify packet is from expected client
        if addr != self.client_address:
            print(f"[SERVER] WARNING: Handshake confirm from unexpected "
                  f"address: {addr} (expected {self.client_address})")
            return
        
        print(f"[SERVER] Received handshake confirm from {addr}")
        
        # Process confirm
        self.handshake_state = handshake_server_process_confirm(
            psk,
            self.handshake_state,
            packet_data
        )
        
        if not self.handshake_state.is_complete():
            print("[SERVER] ERROR: Handshake failed (client MAC verification failed)")
            # Reset state
            self.client_address = None
            self.handshake_state = None
            return
        
        # Store session key
        self.session_key = self.handshake_state.session_key
        
        print(f"[SERVER] ✓ Handshake complete with {addr}!")
        print(f"[SERVER] Session established. Ready to receive data.")
        print()
    
    def _handle_data_packet(self, packet_data, addr):
        """
        Handle encrypted data packet from client.
        
        Args:
            packet_data (bytes): Received packet
            addr (tuple): Sender address
            
        Design:
            Echo server - decrypt message, print it, send it back.
        """
        # Verify packet is from connected client
        if addr != self.client_address:
            print(f"[SERVER] WARNING: Data packet from unknown address: {addr}")
            return
        
        try:
            # Parse packet
            parsed = parse_data_packet(packet_data)
            sequence_number = parsed['sequence_number']
            ciphertext = parsed['ciphertext']
            
            print(f"[SERVER] Received data packet (seq #{sequence_number}, "
                  f"{len(packet_data)} bytes)")
            
            # TODO Phase 5: Check for replay attack
            
            # Decrypt
            nonce = sequence_number.to_bytes(24, 'big')
            plaintext = decrypt_data(self.session_key, ciphertext, nonce)
            
            print(f"[SERVER] Decrypted message: {plaintext.decode('utf-8')}")
            
            # Echo back (send same message back to client)
            self._send_message(plaintext)
            
        except PacketError as e:
            print(f"[SERVER] ERROR: Malformed packet - {e}")
        
        except Exception as e:
            print(f"[SERVER] ERROR handling data packet: {e}")
    
    def _send_message(self, plaintext):
        """
        Send encrypted message to client.
        
        Args:
            plaintext (bytes): Message to send
        """
        if not self.session_key or not self.client_address:
            print("[SERVER] ERROR: Cannot send - no active session")
            return
        
        try:
            # Increment sequence number
            self.sequence_number += 1
            
            # Encrypt
            nonce = self.sequence_number.to_bytes(24, 'big')
            ciphertext = encrypt_data(self.session_key, plaintext, nonce)
            
            # Build packet
            packet = build_data_packet(self.sequence_number, ciphertext)
            
            print(f"[SERVER] Sending response (seq #{self.sequence_number}, "
                  f"{len(packet)} bytes)")
            
            # Send
            self.sock.sendto(packet, self.client_address)
            
        except Exception as e:
            print(f"[SERVER] ERROR sending message: {e}")


def main():
    """
    Main server program.
    
    Design: Simple echo server for testing.
    Accepts one client, echoes messages back.
    """
    print("=" * 60)
    print("MST VPN SERVER")
    print("=" * 60)
    print()
    
    # For testing, use hardcoded PSK
    # Must match client's PSK!
    print("[SERVER] Generating PSK for testing...")
    psk = generate_psk()
    print(f"[SERVER] PSK: {psk.hex()[:40]}...")
    print()
    print("[SERVER] NOTE: Client must use same PSK!")
    print("[SERVER] Copy the PSK hex string to client.")
    print()
    
    # Create and start server
    server = VPNServer()
    server.start(psk)


if __name__ == '__main__':
    main()