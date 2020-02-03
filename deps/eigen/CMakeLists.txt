
add_library(eigen INTERFACE)
target_include_directories(eigen
	SYSTEM INTERFACE
		${CMAKE_CURRENT_LIST_DIR}/include
)
target_compile_definitions(eigen
	INTERFACE
		EIGNEN_HAS_STDSTRING=1
		EIGNEN_HAS_CXX11_RVALUE_REFS=1
)
