set(PDBPARSER_SOURCES
	pdb_file.cpp
	pdb_symbols.cpp
	pdb_types.cpp
	pdb_utils.cpp
)

add_library(retdec-pdbparser STATIC ${PDBPARSER_SOURCES})
target_include_directories(retdec-pdbparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
