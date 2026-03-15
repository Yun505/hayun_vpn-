"""
Replay Attack Simulation

Demonstrates that the system correctly detects and rejects replayed packets.

Attack scenario:
1. Attacker captures legitimate encrypted packet
2. Client sends new messages (server's window advances)
3. Attacker replays old captured packet
4. Server should REJECT the replayed packet
""" 
import time
import threading
import socket
from core.crypto import generate_psk
from client.client import VPNClient
from server.server import VPNServer


def run_server(psk):
    """Run server in background."""
    server = VPNServer(port=9999)
    try:
        server.start(psk)
    except KeyboardInterrupt:
        pass


def simulate_replay_attack():
    """
    Simulate a replay attack.
    
    Steps:
    1. Establish legitimate connection
    2. Send and capture packet
    3. Send more packets (advance server's window)
    4. Replay captured packet
    5. Verify server rejects it
    """
    print("=" * 70)
    print("REPLAY ATTACK SIMULATION")
    print("=" * 70)
    print()
    
    # Setup
    psk = generate_psk()
    print(f"PSK: {psk.hex()[:40]}...")
    print()
    
    # Start server
    print("[ATTACKER] Starting server...")
    server_thread = threading.Thread(target=run_server, args=(psk,), daemon=True)
    server_thread.start()
    time.sleep(0.5)
    
    # Create client
    print("[CLIENT] Connecting to server...")
    client = VPNClient(server_host='127.0.0.1', server_port=9999)
    
    if not client.connect(psk):
        print("✗ Connection failed!")
        return
    
    print("[CLIENT] ✓ Connected!")
    print()
    
    # STEP 1: Send legitimate packet and capture it
    print("=" * 70)
    print("STEP 1: Send legitimate packet")
    print("=" * 70)
    
    message1 = b"First message"
    print(f"[CLIENT] Sending: {message1.decode()}")
    client.send_message(message1)
    time.sleep(0.2)
    
    # CAPTURE THE PACKET
    # In real attack, attacker would sniff network
    # We'll simulate by building packet manually
    from core.protocol import build_data_packet
    from core.crypto import encrypt_data
    
    captured_seq = 1  # We know first data packet is seq #1
    captured_nonce = captured_seq.to_bytes(24, 'big')
    captured_ciphertext = encrypt_data(client.session_key, message1, captured_nonce)
    captured_packet = build_data_packet(captured_seq, captured_ciphertext)
    
    print(f"[ATTACKER] ✓ Captured packet (seq #{captured_seq}, {len(captured_packet)} bytes)")
    print()
    
    # STEP 2: Send more legitimate packets (advance window)
    print("=" * 70)
    print("STEP 2: Send more packets to advance server's window")
    print("=" * 70)
    
    for i in range(5):
        msg = f"Message #{i+2}".encode()
        print(f"[CLIENT] Sending: {msg.decode()}")
        client.send_message(msg)
        response = client.receive_message(timeout=1.0)
        time.sleep(0.1)
    
    print(f"[CLIENT] Sent 5 more packets (seq #2-6)")
    print()
    
    # STEP 3: Replay the captured packet
    print("=" * 70)
    print("STEP 3: REPLAY ATTACK - Resend captured packet")
    print("=" * 70)
    
    print(f"[ATTACKER] Replaying captured packet (seq #{captured_seq})...")
    print(f"[ATTACKER] This is packet from the past!")
    print()
    
    # Create raw socket to send packet directly
    client.sock.sendto(captured_packet, ('127.0.0.1', 9999))

    
    time.sleep(0.5)
    
    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print()
    print("Check server output above:")
    print("  - If you see 'REPLAY ATTACK DETECTED!' → ✓ Protection works!")
    print("  - If you see 'Decrypted message' → ✗ Attack succeeded (bad!)")
    print()
    
    # Cleanup
    client.close()
    
    print("=" * 70)
    print("SIMULATION COMPLETE")
    print("=" * 70)


if __name__ == '__main__':
    simulate_replay_attack()