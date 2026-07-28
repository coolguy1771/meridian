# Set up the examples
add_executable(voice_chat voice_chat.c)
target_link_libraries(voice_chat adaptive_radio m)

add_executable(mesh_test mesh_test.c)
target_link_libraries(mesh_test adaptive_radio m)

add_executable(group_provisioning_demo group_provisioning_demo.c)
target_link_libraries(group_provisioning_demo adaptive_radio m)

# Install targets
install(TARGETS voice_chat mesh_test group_provisioning_demo
    RUNTIME DESTINATION bin/examples
)