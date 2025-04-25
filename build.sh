#!/bin/bash
set -e

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Build the project
cmake ..
make -j$(nproc)

# Run tests
ctest -V

echo "Build completed successfully!"