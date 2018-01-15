set(RETDEC_CONFIGTOOL_SOURCES
	configtool.cpp
)

add_executable(retdec-configtool ${RETDEC_CONFIGTOOL_SOURCES})
set_target_properties(retdec-configtool PROPERTIES OUTPUT_NAME "retdec-config")
target_link_libraries(retdec-configtool retdec-config)
install(TARGETS retdec-configtool RUNTIME DESTINATION bin)
