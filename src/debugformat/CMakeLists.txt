set(DEBUGFORMAT_SOURCES
	debugformat.cpp
	dwarf.cpp
	pdb.cpp
)

add_library(retdec-debugformat STATIC ${DEBUGFORMAT_SOURCES})
target_link_libraries(retdec-debugformat retdec-config retdec-demangler retdec-dwarfparser retdec-pdbparser)
target_include_directories(retdec-debugformat PUBLIC ${PROJECT_SOURCE_DIR}/include/)
