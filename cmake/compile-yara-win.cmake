install(CODE "
	execute_process(
		COMMAND sh \"${CMAKE_SOURCE_DIR}/cmake/compile-yara.sh\" \"${YARAC_DIR}/\${CMAKE_INSTALL_CONFIG_NAME}/${YARAC_NAME}\" \"${CMAKE_SOURCE_DIR}\" \"${CMAKE_INSTALL_PREFIX}\"
		RESULT_VARIABLE COMPILE_YARA_RES
	)
	if(COMPILE_YARA_RES)
		message(FATAL_ERROR \"Yara tool signatures compilation FAILED\")
	endif()
")
