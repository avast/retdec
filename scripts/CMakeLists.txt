
if(RETDEC_ENABLE_RETDEC_DECOMPILER)
	install(
		PROGRAMS "retdec-archive-decompiler.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()

if(RETDEC_ENABLE_FILEINFO)
	install(
		PROGRAMS "retdec-fileinfo.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()

if(RETDEC_TESTS)
	install(
		PROGRAMS "retdec-tests-runner.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()

if(RETDEC_ENABLE_ALL)
	install(
		PROGRAMS "retdec-signature-from-library-creator.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()

if(RETDEC_ENABLE_UNPACKERTOOL)
	install(
		PROGRAMS "retdec-unpacker.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()

if(RETDEC_ENABLE_RETDEC_DECOMPILER
		OR RETDEC_ENABLE_FILEINFO
		OR RETDEC_TESTS
		OR RETDEC_ENABLE_ALL
		OR RETDEC_ENABLE_UNPACKERTOOL)
	install(
		PROGRAMS "retdec-utils.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()
