# Find the Codec2 library
#
# Usage:
#   find_package(Codec2 [REQUIRED])
#
# Once done this will define:
#  Codec2_FOUND         - System has the Codec2 library
#  Codec2_INCLUDE_DIRS  - The Codec2 include directories
#  Codec2_LIBRARIES     - The libraries needed to use Codec2
#  Codec2::Codec2       - Imported target for Codec2

include(FindPackageHandleStandardArgs)

find_path(Codec2_INCLUDE_DIR codec2/codec2.h
  HINTS
  ${CMAKE_INSTALL_PREFIX}/include
  /usr/include
  /usr/local/include
)

find_library(Codec2_LIBRARY
  NAMES codec2
  HINTS
  ${CMAKE_INSTALL_PREFIX}/lib
  ${CMAKE_INSTALL_PREFIX}/lib64
  /usr/lib
  /usr/lib64
  /usr/local/lib
  /usr/local/lib64
)

find_package_handle_standard_args(Codec2
  REQUIRED_VARS Codec2_LIBRARY Codec2_INCLUDE_DIR
)

if(Codec2_FOUND)
  set(Codec2_LIBRARIES ${Codec2_LIBRARY})
  set(Codec2_INCLUDE_DIRS ${Codec2_INCLUDE_DIR})
  
  if(NOT TARGET Codec2::Codec2)
    add_library(Codec2::Codec2 UNKNOWN IMPORTED)
    set_target_properties(Codec2::Codec2 PROPERTIES
      IMPORTED_LOCATION "${Codec2_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${Codec2_INCLUDE_DIR}"
    )
  endif()
endif()

mark_as_advanced(Codec2_INCLUDE_DIR Codec2_LIBRARY)