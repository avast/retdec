set(GETSIG_SOURCES
	getsig.cpp
)

add_executable(retdec-getsig ${GETSIG_SOURCES})
target_link_libraries(retdec-getsig retdec-fileformat llvm)
target_include_directories(retdec-getsig PUBLIC ${PROJECT_SOURCE_DIR}/include/)
install(TARGETS retdec-getsig RUNTIME DESTINATION bin)
