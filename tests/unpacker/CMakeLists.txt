set(RETDEC_TESTS_UNPACKER_SOURCES
	dynamic_buffer_tests.cpp
	signature_tests.cpp
)

add_executable(retdec-tests-unpacker ${RETDEC_TESTS_UNPACKER_SOURCES})
target_link_libraries(retdec-tests-unpacker retdec-unpacker gmock_main)
install(TARGETS retdec-tests-unpacker RUNTIME DESTINATION ${RETDEC_TESTS_DIR})
