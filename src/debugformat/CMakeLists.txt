
add_library(retdec-debugformat STATIC
	debugformat.cpp
	dwarf.cpp
	pdb.cpp
)
target_link_libraries(retdec-debugformat
	retdec-config
	retdec-demangler
	retdec-pdbparser
	retdec-fileformat
	retdec-loader
	retdec-common
	llvm
)
target_include_directories(retdec-debugformat PUBLIC ${PROJECT_SOURCE_DIR}/include/)
