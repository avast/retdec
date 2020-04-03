
add_executable(ar-extractortool
	ar_extractor.cpp
)

target_link_libraries(ar-extractortool
	retdec::ar-extractor
	retdec::utils
	retdec::deps::rapidjson
)

set_target_properties(ar-extractortool
	PROPERTIES
		OUTPUT_NAME "retdec-ar-extractor"
)

install(TARGETS ar-extractortool
	RUNTIME DESTINATION bin
)
