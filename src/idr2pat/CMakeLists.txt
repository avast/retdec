
add_executable(idr2pat
	idr2pat.cpp
)

target_link_libraries(idr2pat retdec::utils yaramod)

set_target_properties(idr2pat
	PROPERTIES
		OUTPUT_NAME "retdec-idb2pat"
)

install(TARGETS idr2pat
	RUNTIME DESTINATION bin
)
