set(DEMANGLER_LLVM_SOURCES
	Allocator.cpp
    ItaniumDemangle.cpp
    MicrosoftDemangle.cpp
    MicrosoftDemangleNodes.cpp
    Demangle.cpp
    )

add_library(llvm-demangler STATIC ${DEMANGLER_LLVM_SOURCES})
target_include_directories(llvm-demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)