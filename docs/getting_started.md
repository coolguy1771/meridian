# Getting Started with Adaptive Radio

This guide will help you set up and start using the Adaptive Multiband Mesh Radio system.

## Prerequisites

### Hardware Requirements

- ESP32-S3 development board
- SX1262/SX1268 LoRa transceiver module
- ATECC608 secure cryptoprocessor (optional but recommended)
- DS3231 RTC module
- Microphone and speaker (or audio codec)
- Antenna system with band-specific matching networks

### Software Requirements

- ESP-IDF or Arduino IDE with ESP32 support
- CMake (version 3.10 or higher)
- GCC or compatible C/C++ compiler
- Git

## Building the Firmware

### Using CMake

1. Clone the repository:
   ```
   git clone https://github.com/username/adaptive-radio.git
   cd adaptive-radio
   ```

2. Create a build directory and run CMake:
   ```
   mkdir build
   cd build
   cmake ..
   ```

3. Build the project:
   ```
   make
   ```

### Running Tests

To run the test suite:

```
cd build
make test
```

Or run individual tests:

```
./tests/test_radio_config
./tests/test_security
./tests/test_packet
```

## Hardware Setup

### Connecting the SX1262/SX1268 LoRa Module

Connect the LoRa module to the ESP32-S3 using the following pins:

| SX126x Pin | ESP32-S3 Pin |
|------------|--------------|
| NSS (CS)   | GPIO 10      |
| SCK        | GPIO 12      |
| MOSI       | GPIO 11      |
| MISO       | GPIO 13      |
| BUSY       | GPIO 14      |
| DIO1       | GPIO 15      |
| NRST       | GPIO 16      |

### Connecting the DS3231 RTC

Connect the DS3231 RTC module to the ESP32-S3 I2C bus:

| DS3231 Pin | ESP32-S3 Pin |
|------------|--------------|
| SDA        | GPIO 21      |
| SCL        | GPIO 22      |
| VCC        | 3.3V         |
| GND        | GND          |

### Connecting the ATECC608 Secure Element

Connect the ATECC608 to the ESP32-S3 I2C bus:

| ATECC608 Pin | ESP32-S3 Pin |
|--------------|--------------|
| SDA          | GPIO 21      |
| SCL          | GPIO 22      |
| VCC          | 3.3V         |
| GND          | GND          |

### Audio Setup

For the audio subsystem, you can either:

1. Use the ESP32-S3's built-in ADC/DAC with an amplifier circuit
2. Use an external I2S audio codec like the MAX98357A

## Running the Examples

### Voice Chat Example

The voice chat example demonstrates the basic functionality of the radio system:

```
cd build/examples
./voice_chat -i 0x0001 -r 0 -e 3
```

This runs the voice chat application with node ID 0x0001, in the Americas region (0), with mixed terrain (3).

### Mesh Test Example

The mesh test example demonstrates the mesh networking capabilities:

```
cd build/examples
./mesh_test -i 0x0001 -t 0x0002 -r 0 -e 3
```

This runs the mesh test application with node ID 0x0001, targeting node ID 0x0002, in the Americas region (0), with mixed terrain (3).

## Next Steps

- Check out the detailed API documentation in the `docs/api` directory
- Explore the example code in the `examples` directory to understand how to use the library
- Modify the terrain settings to optimize for your specific environment
- Experiment with different security modes and cipher options

## Troubleshooting

- If the radio fails to initialize, check your SPI connections
- If encryption/decryption fails, make sure both devices have synchronized their clocks
- For power issues, verify that the battery voltage is above 3.3V
- To diagnose communication problems, enable debug output by adding `-DDEBUG=1` to your build flags