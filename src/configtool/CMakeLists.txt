
add_executable(configtool
	configtool.cpp
)

target_compile_features(configtool PUBLIC cxx_std_17)

target_link_libraries(configtool
	retdec::config
)

set_target_properties(configtool
	PROPERTIES
		OUTPUT_NAME "retdec-config"
)

install(TARGETS configtool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
