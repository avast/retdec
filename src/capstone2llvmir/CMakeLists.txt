
set(CAPSTONE2LLVMIR_SOURCES
	arm/arm_init.cpp
	arm/arm.cpp
	mips/mips_init.cpp
	mips/mips.cpp
	powerpc/powerpc_init.cpp
	powerpc/powerpc.cpp
	x86/x86_init.cpp
	x86/x86.cpp
	capstone2llvmir.cpp
)

add_library(capstone2llvmir STATIC ${CAPSTONE2LLVMIR_SOURCES})
target_link_libraries(capstone2llvmir tl-cpputils capstone llvm)
target_include_directories(capstone2llvmir PUBLIC ${PROJECT_SOURCE_DIR}/include/)
