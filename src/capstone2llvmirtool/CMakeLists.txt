set(CAPSTONE2LLVMIRTOOL_SOURCES
	capstone2llvmir.cpp
)

add_executable(retdec-capstone2llvmirtool ${CAPSTONE2LLVMIRTOOL_SOURCES})
set_target_properties(retdec-capstone2llvmirtool PROPERTIES OUTPUT_NAME "retdec-capstone2llvmir")
target_link_libraries(retdec-capstone2llvmirtool retdec-utils retdec-capstone2llvmir keystone)
install(TARGETS retdec-capstone2llvmirtool RUNTIME DESTINATION bin)
