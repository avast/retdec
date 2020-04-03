
add_library(unpacker STATIC
	decompression/lzma/lzma_data.cpp
	decompression/nrv/nrv2d_data.cpp
	decompression/nrv/nrv2b_data.cpp
	decompression/nrv/nrv2e_data.cpp
	decompression/lzmat/lzmat_data.cpp
	signature.cpp
)
add_library(retdec::unpacker ALIAS unpacker)

target_compile_features(unpacker PUBLIC cxx_std_17)

target_include_directories(unpacker
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(unpacker
	PUBLIC
		retdec::loader
)

# Disable the min() and max() macros to prevent errors when using e.g.
# std::numeric_limits<...>::max()
# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
# Any target that includes "windows.h" needs to define this.
if(MSVC)
	target_compile_definitions(unpacker PUBLIC NOMINMAX)
endif()

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/unpacker
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT unpacker
)

# Install libs.
install(TARGETS unpacker
	EXPORT unpacker-targets
	COMPONENT unpacker
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT unpacker-targets
	FILE "retdec-unpacker-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT unpacker
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-unpacker-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT unpacker
)
