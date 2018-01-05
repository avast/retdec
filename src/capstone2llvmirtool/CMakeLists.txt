
set(CAPSTONE2LLVMIRTOOL_SOURCES
	capstone2llvmir.cpp
)

add_executable(capstone2llvmirtool ${CAPSTONE2LLVMIRTOOL_SOURCES})
set_target_properties(capstone2llvmirtool PROPERTIES OUTPUT_NAME "capstone2llvmir")
target_link_libraries(capstone2llvmirtool tl-cpputils capstone2llvmir keystone)
install(TARGETS capstone2llvmirtool RUNTIME DESTINATION bin)
