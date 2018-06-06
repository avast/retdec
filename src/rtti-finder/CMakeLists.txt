set(RTTI_FINDER_SOURCES
	rtti/rtti_gcc_parser.cpp
	rtti/rtti_msvc_parser.cpp
	vtable/vtable_finder.cpp
	rtti_finder.cpp
)

add_library(retdec-rtti-finder STATIC ${RTTI_FINDER_SOURCES})
target_link_libraries(retdec-rtti-finder retdec-loader retdec-utils)
target_include_directories(retdec-rtti-finder PUBLIC ${PROJECT_SOURCE_DIR}/include/)
