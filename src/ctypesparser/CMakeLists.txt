set(CTYPESPARSER_SOURCES
	ctypes_parser.cpp
	json_ctypes_parser.cpp
	ast_ctypes_parser.cpp
	borland_ast_ctypes_parser.cpp
	ms_ast_ctypes_parser.cpp
	itanium_ast_ctypes_parser.cpp
	type_config.cpp
)

add_library(retdec-ctypesparser STATIC ${CTYPESPARSER_SOURCES})
target_link_libraries(retdec-ctypesparser retdec-ctypes retdec-utils rapidjson retdec-demangler)
target_include_directories(retdec-ctypesparser PUBLIC ${PROJECT_SOURCE_DIR}/include/)
