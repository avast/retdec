set(PATTERNGEN_SOURCES
	pattern_extractor/pattern_extractor.cpp
	pattern_extractor/types/symbol_pattern.cpp
)

add_library(retdec-patterngen STATIC ${PATTERNGEN_SOURCES})
target_link_libraries(retdec-patterngen retdec-fileformat retdec-utils yaramod)
target_include_directories(retdec-patterngen PUBLIC ${PROJECT_SOURCE_DIR}/include/)
