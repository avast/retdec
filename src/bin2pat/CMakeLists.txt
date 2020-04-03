
add_executable(bin2pat
	bin2pat.cpp
)

target_compile_features(bin2pat PUBLIC cxx_std_17)

target_link_libraries(bin2pat
	retdec::patterngen
	retdec::utils
	retdec::deps::yaramod
)

set_target_properties(bin2pat
	PROPERTIES
		OUTPUT_NAME "retdec-bin2pat"
)

install(TARGETS bin2pat
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
