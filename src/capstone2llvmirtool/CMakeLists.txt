
add_executable(capstone2llvmirtool
	capstone2llvmir.cpp
)

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
	RUNTIME DESTINATION bin
)
