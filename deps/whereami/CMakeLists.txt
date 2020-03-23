
add_library(whereami STATIC
	whereami.c
)
target_include_directories(whereami
	INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/whereami/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include/whereami
)
