
set(PDBPARSER_SOURCES
	pdb_file.cpp
	pdb_symbols.cpp
	pdb_types.cpp
	pdb_utils.cpp
)

add_library(pdbparser STATIC ${PDBPARSER_SOURCES})
target_include_directories(pdbparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
