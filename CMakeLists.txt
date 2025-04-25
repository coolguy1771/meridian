cmake_minimum_required(VERSION 3.10)
project(AdaptiveRadio VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTS "Build the test suite" ON)
option(USE_HARDWARE_CRYPTO "Use hardware cryptographic acceleration" ON)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Add main library
add_subdirectory(src)

# Add examples
add_subdirectory(examples)

# Add tests if enabled
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()