
set(IDR2PAT_SOURCES
	idr2pat.cpp
)

add_executable(idr2pat ${IDR2PAT_SOURCES})
target_link_libraries(idr2pat tl-cpputils yaramod)
install(TARGETS idr2pat RUNTIME DESTINATION bin)
