
set(MACHO_EXTRACTOR_SOURCES
	break_fat.cpp
)

if(NOT TARGET macho-extractor)

	add_library(macho-extractor STATIC ${MACHO_EXTRACTOR_SOURCES})
	target_link_libraries(macho-extractor tl-cpputils rapidjson llvm)
	target_include_directories(macho-extractor PUBLIC ${PROJECT_SOURCE_DIR}/include/)

endif()
