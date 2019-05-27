# All installation commands for retdec support are in this single CMake file:
#   1. CMake guarantees the processing order of install rules within the same
#      CMakeLists.txt file
#   2. Listing all the steps one by one in a single place is more clear for
#      developers.

set(CMAKE_INSTALL_MESSAGE LAZY)
set(SUPPORT_TARGET_DIR "${CMAKE_INSTALL_PREFIX}/share/retdec/support")

# Clean support target directory if YARA compilation flag changed.
#
check_if_variable_changed(RETDEC_COMPILE_YARA CHANGED)
if(CHANGED)
	message(STATUS "Support: YARA rules compilation flag changed -> cleaning RetDec support.")
	FILE(REMOVE_RECURSE "${SUPPORT_TARGET_DIR}")
endif()

# Get and install external support package from the retdec-support repository.
# This step may erase the entire target support directory, so it needs to go
# first.
#
install(CODE "
	execute_process(
		# -u = unbuffered -> print debug messages right away.
		COMMAND \"${PYTHON_EXECUTABLE}\" -u \"${CMAKE_SOURCE_DIR}/support/install-share.py\" \"${CMAKE_INSTALL_PREFIX}\"
		RESULT_VARIABLE INSTALL_SHARE_RES
	)
	if(INSTALL_SHARE_RES)
		message(FATAL_ERROR \"RetDec share directory installation FAILED\")
	endif()
")

# Install ordinal number databases.
#
install(DIRECTORY ordinals/arm/ DESTINATION "${SUPPORT_TARGET_DIR}/arm/ords")
install(DIRECTORY ordinals/x86/ DESTINATION "${SUPPORT_TARGET_DIR}/x86/ords")

# Install yara patterns.
#
# Nothing - these are installed by the following Python script.

# Install YARA rules for tools detection.
#
set(YARAC_PATH "${CMAKE_INSTALL_PREFIX}/bin/retdec-yarac${CMAKE_EXECUTABLE_SUFFIX}")
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
