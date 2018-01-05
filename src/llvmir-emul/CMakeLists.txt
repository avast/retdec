
set(LLVMIR_EMUL_SOURCES
	llvmir_emul.cpp
)

add_library(llvmir-emul STATIC ${LLVMIR_EMUL_SOURCES})
target_link_libraries(llvmir-emul llvm)
target_include_directories(llvmir-emul PUBLIC ${PROJECT_SOURCE_DIR}/include/)
