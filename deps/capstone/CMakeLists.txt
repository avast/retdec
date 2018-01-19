include(ExternalProject)

ExternalProject_Add(capstone-project
	URL https://github.com/avast-tl/capstone/archive/27c713fe4f6eaf9721785932d850b6291a6073fe.zip
	URL_HASH SHA256=4d8d0461d7d5737893253698cd0b6d0d64545c1a74b166e8b1d823156a3109cb
	DOWNLOAD_NAME capstone.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DCAPSTONE_BUILD_SHARED=OFF
		-DCAPSTONE_BUILD_STATIC_RUNTIME=OFF
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(capstone-project source_dir)
ExternalProject_Get_Property(capstone-project binary_dir)

# Add libraries.
add_library(capstone INTERFACE)
add_dependencies(capstone capstone-project)
target_include_directories(capstone SYSTEM INTERFACE ${source_dir}/include)
target_link_libraries(capstone INTERFACE debug ${binary_dir}/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(capstone INTERFACE optimized ${binary_dir}/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
