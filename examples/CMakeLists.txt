# Set up the examples
add_executable(voice_chat voice_chat.c)
target_link_libraries(voice_chat adaptive_radio m)

add_executable(mesh_test mesh_test.c)
target_link_libraries(mesh_test adaptive_radio m)

# Install targets
install(TARGETS voice_chat mesh_test
    RUNTIME DESTINATION bin/examples
)