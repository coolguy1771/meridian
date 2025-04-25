cmake_minimum_required(VERSION 3.10)
project(AdaptiveRadio VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add custom module path
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

option(BUILD_TESTS "Build the test suite" ON)
option(USE_HARDWARE_CRYPTO "Use hardware cryptographic acceleration" ON)
option(USE_CODEC2 "Enable Codec2 voice codec" OFF)
option(LIBSODIUM_USE_STATIC_LIBS "Use static libsodium library" OFF)

# Find dependencies
find_package(LibSodium REQUIRED)
if(USE_CODEC2)
    # Try to find Codec2 using the installed CMake config file first
    find_package(codec2 QUIET CONFIG)
    if(codec2_FOUND)
        message(STATUS "Found Codec2 using CMake config")
        # codec2 target is already defined by the config file
    else()
        # Fall back to our custom FindCodec2.cmake
        find_package(Codec2 QUIET)
        if(NOT Codec2_FOUND)
            message(STATUS "Codec2 not found, disabling voice codec support")
            set(USE_CODEC2 OFF)
        endif()
    endif()
endif()

# Define global compilation options
if(LibSodium_FOUND)
    add_compile_definitions(USE_LIBSODIUM=1)
endif()

if(USE_CODEC2)
    add_compile_definitions(USE_CODEC2=1)
endif()

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