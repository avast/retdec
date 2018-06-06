set(LLVM_SUPPORT_SOURCES
	diagnostics.cpp
)

add_library(retdec-llvm-support STATIC ${LLVM_SUPPORT_SOURCES})
target_link_libraries(retdec-llvm-support retdec-utils llvm)
target_include_directories(retdec-llvm-support PUBLIC ${PROJECT_SOURCE_DIR}/include/)
