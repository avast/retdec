
cmake_minimum_required(VERSION 3.6)

include(ExternalProject)

ExternalProject_Add(yaracpp-project
	GIT_REPOSITORY https://github.com/avast-tl/yaracpp.git
	GIT_TAG v1.0
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

ExternalProject_Get_Property(yaracpp-project source_dir)
ExternalProject_Get_Property(yaracpp-project binary_dir)

set(YARA_DIR          ${binary_dir}/deps/yara/src/yara)
set(YARA_INCLUDE_DIR  ${YARA_DIR}/libyara/include)
set(YARA_LIBRARY_NAME "libyara")

if(MSVC)
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(YARA_LIBRARY_NAME "${YARA_LIBRARY_NAME}64")
	else()
		set(YARA_LIBRARY_NAME "${YARA_LIBRARY_NAME}32")
	endif()

	set(YARA_WIN_DIR       ${YARA_DIR}/windows/vs2015)
	set(YARA_LIBRARY_DIR   ${YARA_WIN_DIR}/libyara/$<CONFIGURATION>)
else()
	set(YARA_LIBRARY_DIR   ${YARA_DIR}/libyara/.libs)
endif()

# Add libraries.
add_library(yaracpp INTERFACE)
add_dependencies(yaracpp yaracpp-project)
target_include_directories(yaracpp SYSTEM INTERFACE ${source_dir}/include)
target_include_directories(yaracpp SYSTEM INTERFACE ${YARA_INCLUDE_DIR})
target_link_libraries(yaracpp INTERFACE debug     ${binary_dir}/src/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yaracpp${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaracpp INTERFACE debug     ${YARA_LIBRARY_DIR}/${YARA_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaracpp INTERFACE optimized ${binary_dir}/src/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yaracpp${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaracpp INTERFACE optimized ${YARA_LIBRARY_DIR}/${YARA_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
