# MERIDIAN: Multiband Encrypted Radio for Independent Distance-Intensive Adaptive Networking

Meridian is a secure, multiband LoRa mesh radio firmware designed as an alternative to Meshtastic. It implements end-to-end encryption using X25519 identity keys for pairwise session key derivation, XChaCha20-Poly1305 AEAD encryption of application payloads, and dynamic band selection across 433/868/915 MHz.

## Architecture Overview

### Hardware Targets
- **MCU**: ESP32-C6 (recommended) or ESP32-S3
  - RISC-V dual-core, 160 MHz, hardware crypto acceleration (AES, SHA, ECC/RSA)
- **LoRa Radio**: SX1262 (or SX1280 for ultra-long-range variants)
  - Integrated PA, sub-GHz multi-band operation, low power consumption
- **Secure Element** (optional but recommended): ATECC608B/C or ESP32 built-in crypto module
- **RTC**: DS3231 with separate power domain for timekeeping during sleep
- **Audio**: Codec2-compatible ADC/DAC or external codec chip

### Security Model
Meridian uses a layered security approach:

1. **Identity Layer**: Each node has a long-term X25519 identity key pair stored in flash (encrypted with a device secret). Keys are HMAC-SHA256 integrity-protected and persist across reboots.

2. **Key Exchange**: Nodes establish pairwise sessions via a static identity-based ECDH handshake:
   - Initiator sends `HELLO` with its X25519 identity public key (broadcast)
   - Responder derives shared secret via ECDH(responder_priv, initiator_pub), responds with its own identity public key in `RESPONSE`
   - Both sides derive symmetric session keys using BLAKE2b-based KDF with node IDs as domain separation
   - *Note: Current v1 uses static identity keys only (no ephemeral components). Long-term key compromise would allow decryption of historical traffic. Future versions may add ephemeral ECDH for forward secrecy.*

3. **Packet Encryption**: All data packets use XChaCha20-Poly1305 AEAD (libsodium). Nonces are constructed from a persistent monotonic counter plus randomized low bits, preventing reuse under the same session key.

4. **Replay Protection**: Sliding-window replay trackers per source node reject duplicate or out-of-order sequences within a configurable window (64 packets).

5. **Band Security**: Beacons and handshakes use a network-level shared key; unicast traffic uses per-peer session keys derived from ECDH.

### Protocol Overview
- **Packet Types**: Voice, Handshake, ACK, Beacon, Control, Text, Position
- **Mesh Routing**: Proactive distance-vector with RSSI-weighted route selection
- **Band Selection**: Dynamic band switching based on noise floor measurements and link quality per neighbor
- **Forwarding**: TTL-based multi-hop with seen-packet caching to prevent loops

## Directory Structure

```
src/          Core firmware source
include/      Public API headers
examples/     Buildable example apps (Linux simulation)
tests/        Unit tests for crypto/mesh layers
docs/         Documentation
cmake/        CMake helper modules
```

## Dependencies

- **Required**: libsodium (modern crypto library, provides XChaCha20-Poly1305, X25519, etc.)
- **Optional**: codec2 (voice compression)

Install:
```bash
# Debian/Ubuntu
sudo apt-get install libsodium-dev libcodec2-dev

# Fedora
sudo dnf install libsodium-devel codec2-devel

# macOS
brew install libsodium codec2
```

## Building

### On Linux (simulation/testing mode)
```bash
mkdir -p build && cd build
cmake .. -DBUILD_TESTS=ON
make -j$(nproc)
```

This builds a host-targeted version where the platform layer is stubbed (GPIO/SPI/flash/radio operations simulate success). Useful for testing crypto logic, packet parsing, and handshake flows.

### On ESP32 (ESP-IDF build)
Requires ESP-IDF v5.x+ with CMake toolchain configured. See `docs/getting_started.md` for the complete hardware build setup with ESP-IDF integration and SX126x driver configuration.

```bash
# With ESP-IDF environment loaded:
cmake -G "Ninja" \
  -DCMAKE_TOOLCHAIN_FILE=$IDF_PATH/tools/cmake/toolchain-esp32.cmake \
  ..
cmake --build .
```

## Usage (Simulation)

```bash
cd build

# Run crypto/security tests
./tests/test_security

# Run packet layer tests  
./tests/test_packet

# Run mesh networking demo
./examples/mesh_test

# Run voice chat simulation
./examples/voice_chat
```

## Comparison to Meshtastic

| Feature | Meridian | Meshtastic |
|---------|----------|------------|
| Cipher | XChaCha20-Poly1305 AEAD | AES-128-CCM |
| Key Exchange | Ephemeral X25519 DH per pair | Pre-shared PSK |
| Forward Secrecy | Yes (via ephemeral handshakes) | No (static key reuse) |
| Replay Protection | Sliding-window per source | Basic sequence check |
| Identity Model | Per-node X25519 keys | Shared channel keys |
| Hardware Support | ESP32-C6 + SX1262 target | Many boards, mature firmware |

## License

GNU General Public License v3.0 (GPL-3.0) — see LICENSE file for details.
