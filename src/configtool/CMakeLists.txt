
add_executable(configtool
	configtool.cpp
)

target_link_libraries(configtool retdec::config)

set_target_properties(configtool
	PROPERTIES
		OUTPUT_NAME "retdec-config"
)

install(TARGETS configtool
	RUNTIME DESTINATION bin
)
