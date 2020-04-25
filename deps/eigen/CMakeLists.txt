
include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(eigen_project
	URL ${EIGEN_URL}
	URL_HASH SHA256=${EIGEN_ARCHIVE_SHA256}
	DOWNLOAD_NAME "eigen.zip"
	CMAKE_ARGS
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
	# Disable the install step.
	INSTALL_COMMAND ""
)

add_library(eigen INTERFACE)
add_library(retdec::deps::eigen ALIAS eigen)
add_dependencies(eigen eigen_project)

ExternalProject_Get_Property(eigen_project source_dir)

set(EIGEN_INCLUDE_DIR "${source_dir}/Eigen")

target_include_directories(eigen INTERFACE ${EIGEN_INCLUDE_DIR})
