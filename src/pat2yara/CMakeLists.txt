
add_executable(pat2yara
	compare.cpp
	logic.cpp
	modifications.cpp
	pat2yara.cpp
	processing.cpp
	utils.cpp
)

target_compile_features(pat2yara PUBLIC cxx_std_17)

target_include_directories(pat2yara
	PRIVATE
		${RETDEC_SOURCE_DIR}
)

target_link_libraries(pat2yara
	retdec::patterngen
	retdec::utils
	retdec::deps::yaramod
)

set_target_properties(pat2yara
	PROPERTIES
		OUTPUT_NAME "retdec-pat2yara"
)

install(TARGETS pat2yara
	RUNTIME
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
