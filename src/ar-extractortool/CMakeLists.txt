
set(AR_EXTRACTOR_SOURCES
	ar_extractor.cpp
)

if(NOT TARGET ar-extractortool)

	add_executable(ar-extractortool ${AR_EXTRACTOR_SOURCES})
	set_target_properties(ar-extractortool PROPERTIES OUTPUT_NAME "ar-extractor")
	target_link_libraries(ar-extractortool ar-extractor tl-cpputils rapidjson)
	install(TARGETS ar-extractortool RUNTIME DESTINATION bin)

endif()
