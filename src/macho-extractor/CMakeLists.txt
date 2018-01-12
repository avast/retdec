set(MACHO_EXTRACTOR_SOURCES
	break_fat.cpp
)

add_library(retdec-macho-extractor STATIC ${MACHO_EXTRACTOR_SOURCES})
target_link_libraries(retdec-macho-extractor retdec-utils rapidjson llvm)
target_include_directories(retdec-macho-extractor PUBLIC ${PROJECT_SOURCE_DIR}/include/)
