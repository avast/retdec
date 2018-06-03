set(DEMANGLER_SOURCES
	demangler.cpp
	demtools.cpp
	gparser.cpp
	igrams.cpp
	stgrammars/borlandll.cpp
	stgrammars/gccll.cpp
	stgrammars/msll.cpp
)

add_library(retdec-demangler STATIC ${DEMANGLER_SOURCES})
target_link_libraries(retdec-demangler retdec-utils)
target_include_directories(retdec-demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)
