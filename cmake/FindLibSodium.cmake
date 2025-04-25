# Written in 2016 by Henrik Steffen Gaßmann <henrik@gassmann.onl>
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to the
# public domain worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication
# along with this software. If not, see
#
# http://creativecommons.org/publicdomain/zero/1.0/
#
# Usage:
#     find_package(LibSodium [version] [REQUIRED])
#
# Variables defined:
#     LibSodium_FOUND            - System has the libsodium library
#     LibSodium_INCLUDE_DIR      - The libsodium include directory
#     LibSodium_LIBRARY_DIR      - The directory containing libsodium library
#     LibSodium_LIBRARY          - The libsodium library
#     LibSodium_VERSION          - Libsodium version
#
# Examples:
#     find_package(LibSodium REQUIRED)
#     target_link_libraries(TARGET PRIVATE LibSodium::LibSodium)

include(FindPackageHandleStandardArgs)

# sodium pkg-config?
if(NOT LIBSODIUM_USE_STATIC_LIBS)
    set(_libsodium_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
    if(WIN32)
        set(CMAKE_FIND_LIBRARY_SUFFIXES .dll.a .dll .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    else()
        set(CMAKE_FIND_LIBRARY_SUFFIXES .so .dylib ${CMAKE_FIND_LIBRARY_SUFFIXES})
    endif()
endif()

find_path(LibSodium_INCLUDE_DIR sodium.h
    HINTS ${LibSodium_ROOT_DIR}/include)

if(UNIX)
    # Use pkg-config to get hints about paths
    find_package(PkgConfig QUIET)
    pkg_check_modules(LibSodium_PKG QUIET libsodium)
endif()

# static lib
if(LIBSODIUM_USE_STATIC_LIBS)
    set(_libsodium_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
    if(WIN32)
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a .lib ${CMAKE_FIND_LIBRARY_SUFFIXES})
    else()
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    endif()
endif()

find_library(LibSodium_LIBRARY
    NAMES sodium
    HINTS ${LibSodium_ROOT_DIR}/lib
          ${LibSodium_PKG_LIBRARY_DIRS})

if(LIBSODIUM_USE_STATIC_LIBS)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_libsodium_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES})
endif()

if(LibSodium_INCLUDE_DIR)
    # Extract version information from library
    if(EXISTS "${LibSodium_INCLUDE_DIR}/sodium/version.h")
        file(STRINGS "${LibSodium_INCLUDE_DIR}/sodium/version.h" _version_header
             REGEX "^#define SODIUM_VERSION_STRING[^\r\n]\"([^\n\"]*)\"")
        if(_version_header MATCHES "^#define SODIUM_VERSION_STRING[^\r\n]\"([^\n\"]*)\"")
            set(LibSodium_VERSION "${CMAKE_MATCH_1}")
        endif()
    endif()
endif()

# Find the library again if we're looking for a specific version
if(LibSodium_VERSION)
    find_package_handle_standard_args(LibSodium
        REQUIRED_VARS
            LibSodium_LIBRARY
            LibSodium_INCLUDE_DIR
        VERSION_VAR
            LibSodium_VERSION)
else()
    find_package_handle_standard_args(LibSodium
        REQUIRED_VARS
            LibSodium_LIBRARY
            LibSodium_INCLUDE_DIR)
endif()

if(LibSodium_FOUND)
    set(LibSodium_INCLUDE_DIRS ${LibSodium_INCLUDE_DIR})
    get_filename_component(LibSodium_LIBRARY_DIR ${LibSodium_LIBRARY} DIRECTORY)
    
    # Create imported target
    if(NOT TARGET LibSodium::LibSodium)
        if(LIBSODIUM_USE_STATIC_LIBS)
            add_library(LibSodium::LibSodium STATIC IMPORTED)
        else()
            add_library(LibSodium::LibSodium SHARED IMPORTED)
        endif()
            
        set_target_properties(LibSodium::LibSodium PROPERTIES
            IMPORTED_LOCATION "${LibSodium_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LibSodium_INCLUDE_DIR}")
    endif()
endif()

mark_as_advanced(LibSodium_INCLUDE_DIR LibSodium_LIBRARY)