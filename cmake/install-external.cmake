install(CODE "
	execute_process(
		# -u = unbuffered -> print debug messages right away.
		COMMAND ${PYTHON_EXECUTABLE} -u \"${CMAKE_SOURCE_DIR}/cmake/install-share.py\" \"${CMAKE_INSTALL_PREFIX}\"
		RESULT_VARIABLE INSTALL_SHARE_RES
	)
	if(INSTALL_SHARE_RES)
		message(FATAL_ERROR \"RetDec share directory installation FAILED\")
	endif()
")
