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

## Dependencies

The project has the following dependencies:
- **libsodium** - Modern cryptographic library for security features (required)
- **codec2** - Voice codec for efficient audio transmission (optional)

### Installing Dependencies

#### Debian/Ubuntu
```bash
sudo apt-get install libsodium-dev libcodec2-dev
```

#### macOS
```bash
brew install libsodium codec2
```

#### Windows
For Windows, you can download pre-built binaries from the respective project websites:
- libsodium: https://libsodium.gitbook.io/doc/installation
- codec2: https://github.com/drowe67/codec2

## Building

### Using the build script

The easiest way to build the project is to use the provided build script:

```bash
./build.sh
```

This script will:
1. Create a build directory
2. Run CMake with default options
3. Build the project
4. Run the tests

### Manual build

If you prefer to build manually:

1. Create build directory and navigate to it:
```bash
mkdir -p build
cd build
```

2. Configure with CMake:
```bash
cmake ..
```

3. Build the project:
```bash
make
```

### Build Options

The following CMake options are available:
- `BUILD_TESTS`: Build the test suite (ON by default)
- `USE_HARDWARE_CRYPTO`: Use hardware cryptographic acceleration if available (ON by default)
- `USE_CODEC2`: Enable voice codec support (OFF by default)
- `LIBSODIUM_USE_STATIC_LIBS`: Use static libsodium library instead of shared (OFF by default)

Example:
```bash
cmake .. -DUSE_CODEC2=ON -DLIBSODIUM_USE_STATIC_LIBS=ON
```

## License

This project is released under the MIT License. See the LICENSE file for details.