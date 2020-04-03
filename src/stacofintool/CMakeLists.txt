
add_executable(stacofintool
	stacofin.cpp
)

target_compile_features(stacofintool PUBLIC cxx_std_17)

target_link_libraries(stacofintool
	retdec::stacofin
	retdec::loader
)

set_target_properties(stacofintool
	PROPERTIES
		OUTPUT_NAME "retdec-stacofin"
)

install(TARGETS stacofintool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
