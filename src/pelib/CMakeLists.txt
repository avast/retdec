
add_library(pelib STATIC
	BoundImportDirectory.cpp
	CoffSymbolTable.cpp
	ComHeaderDirectory.cpp
	DebugDirectory.cpp
	ExportDirectory.cpp
	IatDirectory.cpp
	ImageLoader.cpp
	InputBuffer.cpp
	OutputBuffer.cpp
	PeFile.cpp
	PeLibAux.cpp
	RelocationsDirectory.cpp
	ResourceDirectory.cpp
	RichHeader.cpp
	SecurityDirectory.cpp
	ConfigDirectory.cpp
)
add_library(retdec::pelib ALIAS pelib)

target_compile_features(pelib PUBLIC cxx_std_17)

target_include_directories(pelib
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

# Disable all warnings from this library.
if(MSVC)
	target_compile_options(pelib PUBLIC "/w")
else()
	target_compile_options(pelib PUBLIC "-w")
endif()

set_target_properties(pelib
	PROPERTIES
		OUTPUT_NAME "retdec-pelib"
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
	FILE "retdec-pelib-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-pelib-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
