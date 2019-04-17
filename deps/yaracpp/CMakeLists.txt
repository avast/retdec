include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

if(YARACPP_LOCAL_DIR)
	message(STATUS "YaraCpp: using local YaraCpp directory.")

	ExternalProject_Add(yaracpp-project
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${YARACPP_LOCAL_DIR}"
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
	)
	force_configure_step(yaracpp-project)
else()
	message(STATUS "YaraCpp: using remote YaraCpp revision.")

	ExternalProject_Add(yaracpp-project
		URL https://github.com/avast/yaracpp/archive/f5d97cd746398a49b23e62b62994722597407543.zip
		URL_HASH SHA256=fece1814b0fac2888fc3356d414348f065c2d2eff86c27fee39e45b4a0b5e2c6
		DOWNLOAD_NAME yaracpp.zip
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
		LOG_DOWNLOAD ON
		LOG_CONFIGURE ON
		LOG_BUILD ON
	)
endif()

check_if_variable_changed(YARACPP_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(yaracpp-project binary_dir)
	message(STATUS "YaraCpp: path to YaraCpp directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

ExternalProject_Get_Property(yaracpp-project source_dir)
ExternalProject_Get_Property(yaracpp-project binary_dir)

set(YARA_DIR          ${binary_dir}/deps/yara/src/yara)
set(YARA_INCLUDE_DIR  ${YARA_DIR}/libyara/include)
set(YARA_LIBRARY_NAME "libyara")

if(MSVC)
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(YARA_LIBRARY_NAME "${YARA_LIBRARY_NAME}64")
		set(YARAC_NAME "yarac64.exe" CACHE STRING "Yarac binary name" FORCE)
	else()
		set(YARA_LIBRARY_NAME "${YARA_LIBRARY_NAME}32")
		set(YARAC_NAME "yarac32.exe" CACHE STRING "Yarac binary name" FORCE)
	endif()

	set(YARA_WIN_DIR       ${YARA_DIR}/windows/vs2015)
	set(YARA_LIBRARY_DIR   ${YARA_WIN_DIR}/libyara/$<CONFIGURATION>)
	set(YARAC_PATH         ${YARA_WIN_DIR}/\${CMAKE_INSTALL_CONFIG_NAME}/${YARAC_NAME})
else()
	set(YARA_LIBRARY_DIR   ${YARA_DIR}/libyara/.libs)
	set(YARAC_PATH         ${YARA_DIR}/yarac)
endif()

# Add libraries.
add_library(yaracpp INTERFACE)
add_dependencies(yaracpp yaracpp-project)
target_include_directories(yaracpp SYSTEM INTERFACE ${source_dir}/include)
target_include_directories(yaracpp SYSTEM INTERFACE ${YARA_INCLUDE_DIR})
target_link_libraries(yaracpp INTERFACE debug     ${binary_dir}/src/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaracpp${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaracpp INTERFACE debug     ${YARA_LIBRARY_DIR}/${YARA_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaracpp INTERFACE optimized ${binary_dir}/src/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaracpp${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaracpp INTERFACE optimized ${YARA_LIBRARY_DIR}/${YARA_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})

# Install yarac application - we may need it to compile YARA files.
install(PROGRAMS "${YARAC_PATH}" DESTINATION bin RENAME "retdec-yarac${CMAKE_EXECUTABLE_SUFFIX}")
