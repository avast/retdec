# Requirements.
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

include(ExternalProject)

ExternalProject_Add(yaramod-project
	URL https://github.com/avast-tl/yaramod/archive/v1.0.1.zip
	URL_HASH SHA256=20793f99bd1a22e9b743400653d54790a48457ef0ae1cf8f089a1bf3bf38f339
	DOWNLOAD_NAME yaramod.zip
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

ExternalProject_Get_Property(yaramod-project source_dir)
ExternalProject_Get_Property(yaramod-project binary_dir)

# Add libraries.
add_library(yaramod INTERFACE)
add_dependencies(yaramod yaramod-project)
target_include_directories(yaramod SYSTEM INTERFACE ${source_dir}/include)
target_include_directories(yaramod SYSTEM INTERFACE ${source_dir}/deps)
target_include_directories(yaramod SYSTEM INTERFACE ${binary_dir}/src)
target_include_directories(yaramod SYSTEM INTERFACE "${FLEX_INCLUDE_DIRS}")
target_link_libraries(yaramod INTERFACE debug     ${binary_dir}/src/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaramod INTERFACE optimized ${binary_dir}/src/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
