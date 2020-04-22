
add_library(capstone2llvmir STATIC
	arm/arm_init.cpp
	arm/arm.cpp
	arm64/arm64_init.cpp
	arm64/arm64.cpp
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
add_library(retdec::capstone2llvmir ALIAS capstone2llvmir)

target_compile_features(capstone2llvmir PUBLIC cxx_std_17)

target_include_directories(capstone2llvmir
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
	PRIVATE
		$<BUILD_INTERFACE:${RETDEC_SOURCE_DIR}>
)

target_link_libraries(capstone2llvmir
	PUBLIC
		retdec::common
		retdec::deps::capstone
		retdec::deps::llvm
)

set_target_properties(capstone2llvmir
	PROPERTIES
		OUTPUT_NAME "retdec-capstone2llvmir"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/capstone2llvmir
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS capstone2llvmir
	EXPORT capstone2llvmir-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT capstone2llvmir-targets
	FILE "retdec-capstone2llvmir-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-capstone2llvmir-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-capstone2llvmir-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-capstone2llvmir-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)