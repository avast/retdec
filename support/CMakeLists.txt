# All installation commands for retdec support are in this single CMake file:
#   1. CMake guarantees the processing order of install rules within the same
#      CMakeLists.txt file
#   2. Listing all the steps one by one in a single place is more clear for
#      developers.

set(CMAKE_INSTALL_MESSAGE LAZY)
set(SUPPORT_TARGET_DIR "${CMAKE_INSTALL_PREFIX}/share/retdec/support")

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
install(DIRECTORY yara_patterns/signsrch/ DESTINATION "${SUPPORT_TARGET_DIR}/generic/yara_patterns/signsrch")
install(DIRECTORY yara_patterns/tools/ DESTINATION "${SUPPORT_TARGET_DIR}/generic/yara_patterns/tools")

# Compile YARA rules for tools detection.
#
set(YARAC_PATH "${CMAKE_INSTALL_PREFIX}/bin/retdec-yarac${CMAKE_EXECUTABLE_SUFFIX}")
set(YARA_COMPILE_PY "${CMAKE_SOURCE_DIR}/support/compile-yara-new.py")

install(CODE "
	execute_process(
		COMMAND \"${PYTHON_EXECUTABLE}\" -u \"${YARA_COMPILE_PY}\" \"${YARAC_PATH}\" \"${SUPPORT_TARGET_DIR}\"
		RESULT_VARIABLE COMPILE_YARA_RES
	)
	if(COMPILE_YARA_RES)
		message(FATAL_ERROR \"YARA tool signatures compilation FAILED\")
	endif()
")

# Is this necessary?
set(CMAKE_INSTALL_MESSAGE ALWAYS)
