# HAYUN VPN 

An educational VPN implementation built from first principles to understand secure transport protocols under realistic adversarial assumptions.

> Not intended for production use. Does not replace WireGuard or OpenVPN.

---

## Overview

The project implements a UDP-based encrypted tunnel with mutual authentication and replay protection. The project prioritizes correctness and explicit security reasoning over performance or features.

---

## Implementation Status

### Phases 1-5 Complete

**Phase 1 - Cryptographic Foundation**
- ChaCha20-Poly1305 AEAD encryption
- HKDF-SHA256 session key derivation
- HMAC-SHA256 mutual authentication
- Nonce management tied to sequence numbers

**Phase 2 - Protocol Layer**
- Custom wire protocol with version negotiation
- Packet serialization and deserialization
- Handshake and data packet types
- Network byte order (big-endian) encoding

**Phase 3 - Handshake Protocol**
- 3-way mutual authentication
- Timing-safe MAC verification
- State machine for handshake progression
- Session key establishment from PSK

**Phase 4 - Network Layer**
- UDP socket communication
- Client/server architecture
- Interactive CLI for message transmission
- Graceful error handling and timeouts

**Phase 5 - Replay Protection**
- Bitmap-based sliding window (64-packet window, configurable)
- O(1) check and mark operations
- Tolerates out-of-order UDP delivery
- Window resets on new handshake (fresh session isolation)
- Replay simulation using client socket for accurate port matching

---

## Architecture

```
core/crypto.py       ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256
core/protocol.py     Packet serialization, wire format
core/replay.py       SlidingWindow: bitmap-based duplicate detection
client/client.py     VPNClient: handshake, send/receive, replay check
server/server.py     VPNServer: handshake, decrypt, replay enforcement
simulations/         Attack demonstrations
tests/               Unit and integration test suites
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | ChaCha20 stream cipher |
| Integrity | Poly1305 authentication tag |
| Authentication | HMAC-SHA256 handshake |
| Replay protection | Sliding window, seq number tracking |

**Out of scope (known limitations):**
- Traffic analysis (timing, size, frequency visible)
- Forward secrecy (PSK compromise exposes all session traffic)
- Denial of service protection
- Anonymity (IP and metadata visible)

All cryptographic primitives sourced from PyNaCl/libsodium. No custom cryptography.

---

## Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|---|---|---|
| AEAD cipher | ChaCha20-Poly1305 | Authenticated encryption |
| Key derivation | HKDF-SHA256 | Session key generation |
| MAC | HMAC-SHA256 | Handshake authentication |
| RNG | OS CSPRNG via PyNaCl | Nonce generation |

---

## Replay Protection Design

The `SlidingWindow` class tracks a fixed window of recent sequence numbers using a boolean bitmap.

**Decision rationale:**

| Choice | Reason |
|---|---|
| Bitmap over set | Fixed memory, O(1) ops, automatic cleanup |
| Window size 64 | Balances reordering tolerance vs memory |
| Mark after decryption | Prevents marking corrupted or tampered packets |
| Reset on handshake | Prevents cross-session seq number collisions |
| Check on both ends | Defense in depth |

WireGuard uses a 2048-packet window; 64 is used here for simplicity.

---

## Project Structure

```
vpn-project/
├── core/
│   ├── constants.py
│   ├── crypto.py
│   ├── protocol.py
│   └── replay.py
├── client/
│   └── client.py
├── server/
│   └── server.py
├── tests/
│   ├── test_crypto.py
│   ├── test_protocol.py
│   ├── test_handshake.py
│   ├── test_replay.py
│   └── test_integration.py
├── simulations/
│   └── replay_attack.py
├── requirements.txt
└── README.md
```

---

## Setup

**Requirements:** Python 3.10+

```bash
git clone https://github.com/Yun505/vpn-project.git
cd vpn-project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Dependencies:**
```
PyNaCl>=1.5.0
pytest>=7.0.0
cryptography>=41.0.0
```

---

## Usage

**Server:**
```bash
python3 server/server.py
```
Generates a PSK, listens on `0.0.0.0:9999`, and waits for a client connection.

**Client:**
```bash
python3 client/client.py
```
Connects to `127.0.0.1:9999`, performs handshake, enters interactive message mode.

Note: PSK must be shared manually between client and server.

---

## Testing

```bash
pytest -v                          # all tests
pytest tests/test_crypto.py -v    # cryptographic primitives
pytest tests/test_protocol.py -v  # packet serialization
pytest tests/test_handshake.py -v # handshake protocol
pytest tests/test_replay.py -v    # sliding window unit tests
pytest tests/test_integration.py -v # end-to-end
pytest --cov=core --cov=client --cov=server  # with coverage
```

**Test counts:**
- 12 cryptographic function tests
- 18 protocol serialization tests
- 7 handshake protocol tests
- 12 replay window tests
- 10 integration tests

---

## Attack Simulation

```bash
python3 -m simulations.replay_attack
```

Simulation steps:
1. Establishes a legitimate client-server session
2. Captures an encrypted packet (seq #1)
3. Sends additional packets to advance the server's replay window
4. Replays the captured packet using the original client socket (same port)
5. Server detects the duplicate sequence number and rejects it

Expected output includes `REPLAY ATTACK DETECTED! Rejecting seq #1`.

---

## Known Limitations

1. **No forward secrecy** - PSK compromise exposes full session traffic. Planned fix: ephemeral Diffie-Hellman (Noise protocol).
2. **Single client** - Server handles one connection at a time.
3. **Manual key distribution** - PSK shared out-of-band.
4. **No traffic obfuscation** - Packet patterns visible; VPN fingerprinting possible.
5. **User-space only** - No TUN/TAP interface; cannot route IP traffic.

---

## Performance (localhost, Ubuntu 22.04, Python 3.10)

| Metric | Value |
|---|---|
| Handshake time | ~5-10ms |
| Encryption overhead | ~0.1ms per packet |
| Throughput | ~50MB/s |
| Memory per connection | ~15MB |

Performance is not a goal of this project. Production VPNs use kernel-level implementations.

---

## References
- Lots of Computerphile videos 

---
