
set(BIN2PAT_SOURCES
	bin2pat.cpp
)

add_executable(bin2pat ${BIN2PAT_SOURCES})
target_link_libraries(bin2pat patterngen tl-cpputils yaramod)
install(TARGETS bin2pat RUNTIME DESTINATION bin)
