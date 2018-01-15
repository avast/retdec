set(CTYPESPARSER_SOURCES
	ctypes_parser.cpp
	json_ctypes_parser.cpp
)

add_library(retdec-ctypesparser STATIC ${CTYPESPARSER_SOURCES})
target_link_libraries(retdec-ctypesparser retdec-ctypes retdec-utils rapidjson)
target_include_directories(retdec-ctypesparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
