
add_executable(idr2pat
	idr2pat.cpp
)

target_compile_features(idr2pat PUBLIC cxx_std_17)

target_link_libraries(idr2pat
	retdec::utils
	retdec::deps::yaramod
)

set_target_properties(idr2pat
	PROPERTIES
		OUTPUT_NAME "retdec-idr2pat"
)

install(TARGETS idr2pat
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
