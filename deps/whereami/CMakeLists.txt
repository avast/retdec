
add_library(whereami STATIC
	whereami.c
)
add_library(retdec::deps::whereami ALIAS whereami)

target_include_directories(whereami
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/whereami/include>
		# nothing for install because this does not need to be installed
)
