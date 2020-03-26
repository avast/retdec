
add_executable(demanglertool
	demangler.cpp
)

target_link_libraries(demanglertool
	retdec::demangler
)

set_target_properties(demanglertool
	PROPERTIES
		OUTPUT_NAME "retdec-demangler"
)

install(TARGETS demanglertool
	RUNTIME DESTINATION bin
)
