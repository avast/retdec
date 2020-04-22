# All installation commands for retdec support are in this single CMake file:
#   1. CMake guarantees the processing order of install rules within the same
#      CMakeLists.txt file
#   2. Listing all the steps one by one in a single place is more clear for
#      developers.

set(CMAKE_INSTALL_MESSAGE LAZY)
set(SUPPORT_TARGET_DIR "${RETDEC_INSTALL_SUPPORT_DIR_ABS}")
set(YARAC_PATH         "${RETDEC_INSTALL_BIN_DIR_ABS}/retdec-yarac${CMAKE_EXECUTABLE_SUFFIX}")
set(YARAC_VERSION_PATH "${SUPPORT_TARGET_DIR}/version-yarac.txt")

# Clean the support target directory if YARA compilation flag changed.
#
check_if_variable_changed(RETDEC_COMPILE_YARA CHANGED)
if(CHANGED)
	message(STATUS "Support: YARA rules compilation flag changed -> cleaning RetDec support.")
	FILE(REMOVE_RECURSE "${SUPPORT_TARGET_DIR}")
endif()

# Clean the support target directory if yarac version changed.
# Also clean it if there is no yarac version file - we cannot be sure what
# version was used in such a case.
#
install(CODE "
	if(EXISTS \"${YARAC_VERSION_PATH}\")
		file(READ \"${YARAC_VERSION_PATH}\" YARAC_OLD_VERSION)
		execute_process(
			COMMAND \"${YARAC_PATH}\" --version
			OUTPUT_VARIABLE YARAC_CURRENT_VERSION
			OUTPUT_STRIP_TRAILING_WHITESPACE
		)
		if(YARAC_OLD_VERSION STREQUAL YARAC_CURRENT_VERSION)
			message(STATUS \"Up-to-date: yarac version '\${YARAC_OLD_VERSION}'\")
		else()
			message(STATUS \"Previously used yarac version '\${YARAC_OLD_VERSION}' \
does not match the current version '\${YARAC_CURRENT_VERSION}' \
-> clean the support directory\")
			FILE(REMOVE_RECURSE \"${SUPPORT_TARGET_DIR}\")
		endif()
	elseif(EXISTS \"${SUPPORT_TARGET_DIR}\")
		message(STATUS \"yarac version does not exist \
-> clean the support directory\")
		FILE(REMOVE_RECURSE \"${SUPPORT_TARGET_DIR}\")
	else()
		# Support directory itself does not yet exist.
	endif()
")

# Get and install external support package from the retdec-support repository.
# This step may erase the entire target support directory, so it needs to go
# first.
#
install(CODE "
	execute_process(
		# -u = unbuffered -> print debug messages right away.
		COMMAND \"${PYTHON_EXECUTABLE}\" -u \"${CMAKE_SOURCE_DIR}/support/install-share.py\" \"${CMAKE_INSTALL_PREFIX}\" \"${SUPPORT_PKG_URL}\" \"${SUPPORT_PKG_SHA256}\" \"${SUPPORT_PKG_VERSION}\"
		RESULT_VARIABLE INSTALL_SHARE_RES
	)
	if(INSTALL_SHARE_RES)
		message(FATAL_ERROR \"RetDec share directory installation FAILED\")
	endif()
")

# Write currently used yarac version to the support directory.
#
install(CODE "
	execute_process(
		COMMAND \"${YARAC_PATH}\" --version
		OUTPUT_VARIABLE YARAC_CURRENT_VERSION
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	message(STATUS \"yarac version '\${YARAC_CURRENT_VERSION}' \
written to '${YARAC_VERSION_PATH}'\")
	file(WRITE \"${YARAC_VERSION_PATH}\" \"\${YARAC_CURRENT_VERSION}\")
")

# Install ordinal number databases.
#
install(
	DIRECTORY ordinals/arm/
	DESTINATION ${SUPPORT_TARGET_DIR}/arm/ords
)
install(
	DIRECTORY ordinals/x86/
	DESTINATION ${SUPPORT_TARGET_DIR}/x86/ords
)

# Install yara patterns.
#
# Nothing - these are installed by the following Python script.

# Install YARA rules for tools detection.
#
set(YARA_INSTALL_PY "${CMAKE_SOURCE_DIR}/support/install-yara.py")

install(CODE "
	execute_process(
		COMMAND \"${PYTHON_EXECUTABLE}\" -u \"${YARA_INSTALL_PY}\"
			\"${YARAC_PATH}\"
			\"${SUPPORT_TARGET_DIR}\"
			\"${CMAKE_SOURCE_DIR}/support/yara_patterns\"
			${RETDEC_COMPILE_YARA}
		RESULT_VARIABLE INSTALL_YARA_RES
	)
	if(INSTALL_YARA_RES)
		message(FATAL_ERROR \"YARA tool signatures installation FAILED\")
	endif()
")

# Is this necessary?
set(CMAKE_INSTALL_MESSAGE ALWAYS)
