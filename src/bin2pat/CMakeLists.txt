set(BIN2PAT_SOURCES
	bin2pat.cpp
)

add_executable(retdec-bin2pat ${BIN2PAT_SOURCES})
target_link_libraries(retdec-bin2pat retdec-patterngen retdec-utils yaramod)
install(TARGETS retdec-bin2pat RUNTIME DESTINATION bin)
