set(IDR2PAT_SOURCES
	idr2pat.cpp
)

add_executable(retdec-idr2pat ${IDR2PAT_SOURCES})
target_link_libraries(retdec-idr2pat retdec-utils yaramod)
install(TARGETS retdec-idr2pat RUNTIME DESTINATION bin)
