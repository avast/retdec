set(CAPSTONE2LLVMIR_SOURCES
	arm/arm_init.cpp
	arm/arm.cpp
	mips/mips_init.cpp
	mips/mips.cpp
	powerpc/powerpc_init.cpp
	powerpc/powerpc.cpp
	x86/x86_init.cpp
	x86/x86.cpp
	capstone2llvmir_impl.cpp
	capstone2llvmir.cpp
	exceptions.cpp
	llvmir_utils.cpp
)

add_library(retdec-capstone2llvmir STATIC ${CAPSTONE2LLVMIR_SOURCES})
target_link_libraries(retdec-capstone2llvmir retdec-utils capstone llvm)
target_include_directories(retdec-capstone2llvmir PUBLIC ${PROJECT_SOURCE_DIR}/include/)
target_include_directories(retdec-capstone2llvmir PUBLIC ${PROJECT_SOURCE_DIR}/src/)
