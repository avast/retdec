
add_executable(demanglertool
	demangler.cpp
)

target_compile_features(demanglertool PUBLIC cxx_std_17)

target_link_libraries(demanglertool
	retdec::demangler
)

set_target_properties(demanglertool
	PROPERTIES
		OUTPUT_NAME "retdec-demangler"
)

install(TARGETS demanglertool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
