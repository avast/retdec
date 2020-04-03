
add_executable(pat2yara
	compare.cpp
	logic.cpp
	modifications.cpp
	pat2yara.cpp
	processing.cpp
	utils.cpp
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

target_include_directories(pat2yara
	PRIVATE
		${RETDEC_SOURCE_DIR}
)

install(TARGETS pat2yara
	RUNTIME
		DESTINATION bin
)
