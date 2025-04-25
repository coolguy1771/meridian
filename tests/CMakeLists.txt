# Include headers
include_directories(${PROJECT_SOURCE_DIR}/include)

# Create test executables
add_executable(test_radio_config test_radio_config.c)
target_link_libraries(test_radio_config adaptive_radio)

add_executable(test_security test_security.c)
target_link_libraries(test_security adaptive_radio)

add_executable(test_packet test_packet.c)
target_link_libraries(test_packet adaptive_radio)

# Add tests
enable_testing()
add_test(NAME RadioConfig COMMAND test_radio_config)
add_test(NAME Security COMMAND test_security)
add_test(NAME Packet COMMAND test_packet)