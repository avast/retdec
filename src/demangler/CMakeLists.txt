
set(DEMANGLER_SOURCES
	demangler.cpp
	demtools.cpp
	gparser.cpp
	igrams.cpp
	stgrammars/borlandll.cpp
	stgrammars/gccll.cpp
	stgrammars/msll.cpp
)

add_library(demangler STATIC ${DEMANGLER_SOURCES})
target_include_directories(demangler PUBLIC ${PROJECT_SOURCE_DIR}/include/)
