
add_executable(getsig
	getsig.cpp
)

target_link_libraries(getsig
	retdec::fileformat
)

set_target_properties(getsig
	PROPERTIES
		OUTPUT_NAME "retdec-getsig"
)

install(TARGETS getsig
	RUNTIME DESTINATION bin
)
