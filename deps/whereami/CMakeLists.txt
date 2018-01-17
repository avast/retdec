set(WHEREAMI_SOURCES
	whereami.c
)

if(NOT TARGET whereami)

	add_library(whereami STATIC ${WHEREAMI_SOURCES})
	target_include_directories(whereami PUBLIC ${CMAKE_CURRENT_LIST_DIR})

endif()
