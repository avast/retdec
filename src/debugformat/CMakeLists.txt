set(DEBUGFORMAT_SOURCES
	debugformat.cpp
	dwarf.cpp
	pdb.cpp
)

add_library(debugformat STATIC ${DEBUGFORMAT_SOURCES})
target_link_libraries(debugformat retdec-config demangler dwarfparser pdbparser)
target_include_directories(debugformat PUBLIC ${PROJECT_SOURCE_DIR}/include/)
