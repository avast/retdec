
set(AR_EXTRACTOR_SOURCES
	archive_wrapper.cpp
	detection.cpp
)

if(NOT TARGET ar-extractor)

	add_library(ar-extractor STATIC ${AR_EXTRACTOR_SOURCES})
	target_link_libraries(ar-extractor tl-cpputils rapidjson llvm)
	target_include_directories(ar-extractor PUBLIC ${PROJECT_SOURCE_DIR}/include/)

endif()
