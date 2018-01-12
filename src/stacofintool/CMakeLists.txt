set(STACOFINTOOL_SOURCES
	stacofin.cpp
)

add_executable(retdec-stacofintool ${STACOFINTOOL_SOURCES})
set_target_properties(retdec-stacofintool PROPERTIES OUTPUT_NAME "retdec-stacofin")
target_link_libraries(retdec-stacofintool retdec-stacofin retdec-loader)
install(TARGETS retdec-stacofintool RUNTIME DESTINATION bin)
