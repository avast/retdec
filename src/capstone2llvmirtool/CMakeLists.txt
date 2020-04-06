
add_executable(capstone2llvmirtool
	capstone2llvmir.cpp
)

target_compile_features(capstone2llvmirtool PUBLIC cxx_std_17)

target_link_libraries(capstone2llvmirtool
	retdec::utils
	retdec::capstone2llvmir
	retdec::deps::keystone
)

set_target_properties(capstone2llvmirtool
	PROPERTIES
		OUTPUT_NAME "retdec-capstone2llvmir"
)

install(TARGETS capstone2llvmirtool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
