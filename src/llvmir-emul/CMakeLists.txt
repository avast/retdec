set(LLVMIR_EMUL_SOURCES
	llvmir_emul.cpp
)

add_library(retdec-llvmir-emul STATIC ${LLVMIR_EMUL_SOURCES})
target_link_libraries(retdec-llvmir-emul llvm)
target_include_directories(retdec-llvmir-emul PUBLIC ${PROJECT_SOURCE_DIR}/include/)
