# MERIDIAN: Multiband Encrypted Radio for Independent Distance-Intensive Adaptive Networking

MERIDIAN is an implementation of an adaptive multiband mesh radio system with advanced security architecture for secure long-range communications.

## Features

- **Multiband Operation**: Dynamically selects between multiple frequency bands (433 MHz, 868 MHz, 915 MHz) based on environmental conditions and regulatory requirements
- **Mesh Networking**: Multi-hop communication to extend effective range
- **Advanced Security**: End-to-end encryption with guarantees against nonce reuse and replay attacks
- **Voice Communication**: Codec2 integration for efficient voice compression
- **Regulatory Compliance**: Automatically adapts to regional frequency regulations

## Hardware Requirements

- ESP32-S3 microcontroller
- SX1262/SX1268 LoRa transceiver
- ATECC608 secure cryptoprocessor
- DS3231 RTC with separate power domain
- Audio codec or ADC/DAC
- Antenna system with band-specific matching networks

## Directory Structure

- `src/`: Source code for the radio implementation
- `include/`: Header files
- `lib/`: External libraries and dependencies
- `docs/`: Documentation
- `examples/`: Example applications
- `tests/`: Unit tests

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## License

This project is released under the MIT License. See the LICENSE file for details.