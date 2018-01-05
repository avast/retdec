
set(PATTERNGEN_SOURCES
	pattern_extractor/pattern_extractor.cpp
	pattern_extractor/types/symbol_pattern.cpp
)

add_library(patterngen STATIC ${PATTERNGEN_SOURCES})
target_link_libraries(patterngen fileformat tl-cpputils yaramod)
target_include_directories(patterngen PUBLIC ${PROJECT_SOURCE_DIR}/include/)
