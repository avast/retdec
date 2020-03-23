
add_library(pelib STATIC
	BoundImportDirectory.cpp
	CoffSymbolTable.cpp
	ComHeaderDirectory.cpp
	DebugDirectory.cpp
	ExportDirectory.cpp
	IatDirectory.cpp
	InputBuffer.cpp
	MzHeader.cpp
	OutputBuffer.cpp
	PeFile.cpp
	PeHeader.cpp
	PeLibAux.cpp
	RelocationsDirectory.cpp
	ResourceDirectory.cpp
	RichHeader.cpp
	SecurityDirectory.cpp
)

target_include_directories(pelib
	PUBLIC
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}/retdec>
)

# Disable all warnings from this library.
if(MSVC)
	target_compile_options(pelib PUBLIC "/w")
else()
	target_compile_options(pelib PUBLIC "-w")
endif()

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/pelib/pelib-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/pelib
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS pelib
	EXPORT pelib-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT pelib-targets
	FILE "pelib-targets.cmake"
#	NAMESPACE RetDec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR} #/pelib
)

# Install CMake files.
install(
	FILES
		"${RETDEC_SHARE_DIR}/pelib/pelib-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/pelib/pelib-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
#		"${RETDEC_INSTALL_CMAKE_DIR}/pelib"
)
