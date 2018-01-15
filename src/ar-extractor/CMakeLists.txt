set(AR_EXTRACTOR_SOURCES
	archive_wrapper.cpp
	detection.cpp
)

add_library(retdec-ar-extractor STATIC ${AR_EXTRACTOR_SOURCES})
target_link_libraries(retdec-ar-extractor retdec-utils rapidjson llvm)
target_include_directories(retdec-ar-extractor PUBLIC ${PROJECT_SOURCE_DIR}/include/)
