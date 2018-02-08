set(CPDETECT_SOURCES
	compiler_detector/coff_compiler.cpp
	compiler_detector/compiler_detector.cpp
	compiler_detector/elf_compiler.cpp
	compiler_detector/heuristics/elf_heuristics.cpp
	compiler_detector/heuristics/heuristics.cpp
	compiler_detector/heuristics/macho_heuristics.cpp
	compiler_detector/heuristics/pe_heuristics.cpp
	compiler_detector/intel_hex_compiler.cpp
	compiler_detector/macho_compiler.cpp
	compiler_detector/pe_compiler.cpp
	compiler_detector/raw_data_compiler.cpp
	compiler_detector/search/search.cpp
	compiler_factory.cpp
	cptypes.cpp
	errors.cpp
	signatures/avg/signature.cpp
	signatures/avg/signature_checker.cpp
	utils/version_solver.cpp
)

add_library(retdec-cpdetect STATIC ${CPDETECT_SOURCES})
target_link_libraries(retdec-cpdetect libdwarf retdec-fileformat yaracpp tinyxml2)
target_include_directories(retdec-cpdetect PUBLIC ${PROJECT_SOURCE_DIR}/include/)
