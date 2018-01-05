
set(PAT2YARA_SOURCES
	compare.cpp
	logic.cpp
	modifications.cpp
	pat2yara.cpp
	processing.cpp
	utils.cpp
)

add_executable(pat2yara ${PAT2YARA_SOURCES})
target_link_libraries(pat2yara patterngen tl-cpputils yaramod)
target_include_directories(pat2yara PUBLIC ${PROJECT_SOURCE_DIR}/src/)
install(TARGETS pat2yara RUNTIME DESTINATION bin)
