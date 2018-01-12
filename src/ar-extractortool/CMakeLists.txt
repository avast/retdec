set(AR_EXTRACTOR_SOURCES
	ar_extractor.cpp
)

add_executable(retdec-ar-extractortool ${AR_EXTRACTOR_SOURCES})
set_target_properties(retdec-ar-extractortool PROPERTIES OUTPUT_NAME "retdec-ar-extractor")
target_link_libraries(retdec-ar-extractortool retdec-ar-extractor retdec-utils rapidjson)
install(TARGETS retdec-ar-extractortool RUNTIME DESTINATION bin)
