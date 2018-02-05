install(CODE "
	set(YARAC_PATH \"${YARAC_PATH}\")
	execute_process(
		COMMAND sh \"${CMAKE_SOURCE_DIR}/cmake/install-share.sh\" \"${CMAKE_INSTALL_PREFIX}\"
		RESULT_VARIABLE INSTALL_SHARE_RES
	)
	if(INSTALL_SHARE_RES)
		message(FATAL_ERROR \"RetDec share directory installation FAILED\")
	endif()
	if(MSVC)
		execute_process(
			COMMAND sh \"${CMAKE_SOURCE_DIR}/cmake/compile-yara.sh\" \"${YARAC_DIR}/\${CMAKE_INSTALL_CONFIG_NAME}/${YARAC_NAME}\" \"${CMAKE_SOURCE_DIR}\" \"${CMAKE_INSTALL_PREFIX}\"
			RESULT_VARIABLE COMPILE_YARA_RES
		)
		if(COMPILE_YARA_RES)
			message(FATAL_ERROR \"Yara tool signatures compilation FAILED\")
		endif()
	else()
		execute_process(
			COMMAND sh \"${CMAKE_SOURCE_DIR}/cmake/compile-yara.sh\" \"${YARAC_PATH}\" \"${CMAKE_SOURCE_DIR}\" \"${CMAKE_INSTALL_PREFIX}\"
			RESULT_VARIABLE COMPILE_YARA_RES
		)
		if(COMPILE_YARA_RES)
			message(FATAL_ERROR \"Yara tool signatures compilation FAILED\")
		endif()
	endif()
")
