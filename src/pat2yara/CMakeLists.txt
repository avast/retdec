set(PAT2YARA_SOURCES
	compare.cpp
	logic.cpp
	modifications.cpp
	pat2yara.cpp
	processing.cpp
	utils.cpp
)

add_executable(retdec-pat2yara ${PAT2YARA_SOURCES})
target_link_libraries(retdec-pat2yara retdec-patterngen retdec-utils yaramod)
target_include_directories(retdec-pat2yara PUBLIC ${PROJECT_SOURCE_DIR}/src/)
install(TARGETS retdec-pat2yara RUNTIME DESTINATION bin)
