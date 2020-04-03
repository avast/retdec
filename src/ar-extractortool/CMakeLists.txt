
add_executable(ar-extractortool
	ar_extractor.cpp
)

target_compile_features(ar-extractortool PUBLIC cxx_std_17)

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
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
