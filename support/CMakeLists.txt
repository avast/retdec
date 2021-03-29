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
if(RETDEC_ENABLE_SUPPORT_YARA_SIGNSRCH OR RETDEC_ENABLE_SUPPORT_YARA_TOOLS OR RETDEC_ENABLE_SUPPORT_YARA_STATIC_CODE)
	check_if_variable_changed(RETDEC_COMPILE_YARA CHANGED)
	if(CHANGED)
		message(STATUS "Support: YARA rules compilation flag changed -> cleaning RetDec support.")
		FILE(REMOVE_RECURSE "${SUPPORT_TARGET_DIR}")
	endif()
endif()

# Clean the support target directory if yarac version changed.
# Also clean it if there is no yarac version file - we cannot be sure what
# version was used in such a case.
#
if(RETDEC_ENABLE_SUPPORT_YARA_SIGNSRCH OR RETDEC_ENABLE_SUPPORT_YARA_TOOLS OR RETDEC_ENABLE_SUPPORT_YARA_STATIC_CODE)
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
endif()

# Get and install external support package from the retdec-support repository.
# This step may erase the entire target support directory, so it needs to go
# first.
#
if(RETDEC_ENABLE_SUPPORT_YARA_STATIC_CODE)
	install(CODE "
		execute_process(
			# -u = unbuffered -> print debug messages right away.
			COMMAND \"${PYTHON_EXECUTABLE}\" -u \"${PROJECT_SOURCE_DIR}/support/install-share.py\" \"${CMAKE_INSTALL_PREFIX}\" \"${SUPPORT_PKG_URL}\" \"${SUPPORT_PKG_SHA256}\" \"${SUPPORT_PKG_VERSION}\"
			RESULT_VARIABLE INSTALL_SHARE_RES
		)
		if(INSTALL_SHARE_RES)
			message(FATAL_ERROR \"RetDec share directory installation FAILED\")
		endif()
	")
endif()

# Write currently used yarac version to the support directory.
#
if(RETDEC_ENABLE_SUPPORT_YARA_SIGNSRCH OR RETDEC_ENABLE_SUPPORT_YARA_TOOLS OR RETDEC_ENABLE_SUPPORT_YARA_STATIC_CODE)
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
endif()

# Install ordinal number databases.
#
if(RETDEC_ENABLE_SUPPORT_ORDINALS)
	install(
		DIRECTORY ordinals
		DESTINATION ${SUPPORT_TARGET_DIR}/
	)
endif()

# Install yara patterns.
#
# Nothing - these are installed by the following Python script.

# Install YARA rules for tools detection.
#
if(RETDEC_ENABLE_SUPPORT_YARA_SIGNSRCH OR RETDEC_ENABLE_SUPPORT_YARA_TOOLS)
	set(YARA_INSTALL_PY "${PROJECT_SOURCE_DIR}/support/install-yara.py")
	install(CODE "
		execute_process(
			COMMAND \"${PYTHON_EXECUTABLE}\" -u \"${YARA_INSTALL_PY}\"
				\"${YARAC_PATH}\"
				\"${SUPPORT_TARGET_DIR}\"
				\"${PROJECT_SOURCE_DIR}/support/yara_patterns\"
				${RETDEC_COMPILE_YARA}
			RESULT_VARIABLE INSTALL_YARA_RES
		)
		if(INSTALL_YARA_RES)
			message(FATAL_ERROR \"YARA tool signatures installation FAILED\")
		endif()
	")
endif()

# Is this necessary?
set(CMAKE_INSTALL_MESSAGE ALWAYS)
