
set(STACOFINTOOL_SOURCES
	stacofin.cpp
)

add_executable(stacofintool ${STACOFINTOOL_SOURCES})
set_target_properties(stacofintool PROPERTIES OUTPUT_NAME "stacofin")
target_link_libraries(stacofintool stacofin loader)
install(TARGETS stacofintool RUNTIME DESTINATION bin)
