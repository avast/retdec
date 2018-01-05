
set(STACOFIN_SOURCES
	stacofin.cpp
)

add_library(stacofin STATIC ${STACOFIN_SOURCES})
target_link_libraries(stacofin loader tl-cpputils yaracpp)
target_include_directories(stacofin PUBLIC ${PROJECT_SOURCE_DIR}/include/)
