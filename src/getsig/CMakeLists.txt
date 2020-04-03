
add_executable(getsig
	getsig.cpp
)

target_compile_features(getsig PUBLIC cxx_std_17)

target_link_libraries(getsig
	retdec::fileformat
)

set_target_properties(getsig
	PROPERTIES
		OUTPUT_NAME "retdec-getsig"
)

install(TARGETS getsig
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
