set(LLVM_SUPPORT_SOURCES
	diagnostics.cpp
	utils.cpp
)

add_library(llvm-support STATIC ${LLVM_SUPPORT_SOURCES})
target_link_libraries(llvm-support tl-cpputils llvm)
target_include_directories(llvm-support PUBLIC ${PROJECT_SOURCE_DIR}/include/)
