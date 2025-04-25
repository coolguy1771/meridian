# Source files for the main library
set(SOURCES
    radio_config.c
    security.c
    packet.c
    audio.c
    radio.c
    mesh.c
    rtc.c
    platform.c
)

# Create the main library
add_library(adaptive_radio STATIC ${SOURCES})

# Include directories
target_include_directories(adaptive_radio PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# Conditionally link with hardware crypto library
if(USE_HARDWARE_CRYPTO)
    target_compile_definitions(adaptive_radio PRIVATE USE_HARDWARE_CRYPTO=1)
endif()

# Install targets
install(TARGETS adaptive_radio
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/
    DESTINATION include/adaptive_radio
)