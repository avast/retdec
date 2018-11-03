set(DEMANGLER_LLVM_SOURCES
		ItaniumDemangle.cpp
		MicrosoftDemangle.cpp
		MicrosoftDemangleNodes.cpp
		)

add_library(llvm-demangler STATIC ${DEMANGLER_LLVM_SOURCES})
target_include_directories(llvm-demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)