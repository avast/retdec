set(PELIB_SOURCES
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

add_library(pelib STATIC ${PELIB_SOURCES})
target_include_directories(pelib
	PUBLIC ${PROJECT_SOURCE_DIR}/include/
	PUBLIC ${PROJECT_SOURCE_DIR}/include/retdec)

# Disable all warnings from this library.
if(MSVC)
	target_compile_options(pelib PUBLIC "/w")
else()
	target_compile_options(pelib PUBLIC "-w")
endif()
