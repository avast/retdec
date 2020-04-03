
install(
	PROGRAMS "retdec-config.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
install(
	PROGRAMS "retdec-archive-decompiler.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
install(
	PROGRAMS "retdec-decompiler.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
install(
	PROGRAMS "retdec-fileinfo.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)

if(RETDEC_TESTS)
	install(
		PROGRAMS "retdec-tests-runner.py"
		DESTINATION ${RETDEC_INSTALL_BIN_DIR}
	)
endif()

install(
	PROGRAMS "retdec-signature-from-library-creator.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
install(
	PROGRAMS "retdec-unpacker.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
install(
	PROGRAMS "retdec-utils.py"
	DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
