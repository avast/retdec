
add_executable(stacofintool
	stacofin.cpp
)

target_link_libraries(stacofintool
	retdec::stacofin
	retdec::loader
)

set_target_properties(stacofintool
	PROPERTIES
		OUTPUT_NAME "retdec-stacofin"
)

install(TARGETS stacofintool
	RUNTIME DESTINATION bin
)
