
add_library(retdec STATIC
    retdec.cpp
)
add_library(retdec::retdec ALIAS retdec)

target_compile_features(retdec PUBLIC cxx_std_17)

target_include_directories(retdec
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into retdec as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like
	# that, its properties (associated includes, etc.) are not propagated.
	# Therefore, we state 'bin2llvmir' twice in target_link_libraries(),
	# first as a target to get its properties, second as path to library
	# to link it as a whole.
	target_link_libraries(retdec
		retdec::bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::bin2llvmir>
	)
	set_property(TARGET retdec
		APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE"
	)
	# Allow the 32b version of bin2llvmir on Windows handle addresses larger
	# than 2 GB (up to 4 GB).
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set_property(TARGET retdec
			APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE"
		)
	endif()
elseif(APPLE)
	target_link_libraries(retdec
		-Wl,-force_load retdec::bin2llvmir
	)
else() # Linux
	target_link_libraries(retdec
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
	)
endif()

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-retdec-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/retdec
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT retdec
)

# Install libs.
install(TARGETS retdec
	EXPORT retdec-targets
	COMPONENT retdec
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT retdec-targets
	FILE "retdec-retdec-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT retdec
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-retdec-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-retdec-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT retdec
)
