
set(CTYPESPARSER_SOURCES
	ctypes_parser.cpp
	json_ctypes_parser.cpp
)

add_library(ctypesparser STATIC ${CTYPESPARSER_SOURCES})
target_link_libraries(ctypesparser ctypes tl-cpputils rapidjson)
target_include_directories(ctypesparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
