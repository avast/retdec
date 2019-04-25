find_package(Threads REQUIRED)
if(UNIX)
	find_package(ZLIB REQUIRED)
endif()

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

# Set the default build type to 'Release'
if(NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(IS_DEBUG_BUILD "YES")
else()
	set(IS_DEBUG_BUILD "NO")
endif()

# Use the ExternalProject module instead of just CMake because we want to build and
# install only some tools from LLVM, not all the libraries and tools.
include(ExternalProject)

if(LLVM_LOCAL_DIR)
	message(STATUS "LLVM: using local LLVM directory.")
	
	ExternalProject_Add(llvm-project
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${LLVM_LOCAL_DIR}"
		CMAKE_ARGS
			# Force a release build (we don't need to debug LLVM).
			# This has no effect on Windows with MSVC, but is useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			-DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
	
			# Force Python3.
			-DPYTHON_EXECUTABLE=${PYTHON_EXECUTABLE}
	
			# Targets to be build.
			-DLLVM_TARGETS_TO_BUILD=X86
	
			# Our tools depending on LLVM require RTTI, so build LLVM with it.
			-DLLVM_REQUIRES_RTTI=YES
	
			# When building in the debug mode (=> assertions are enabled), we
			# have to build LLVM with assertions. This prevents link errors
			# when building the middle-end and back-end (see
			# https://github.com/oclint/oclint/issues/129).
			-DLLVM_ENABLE_ASSERTIONS=${IS_DEBUG_BUILD}
	
			# Disable the emission of warnings, which are useless since we do
			# not modify the LLVM sources (of course, except for a few
			# exceptions).
			-DLLVM_ENABLE_WARNINGS=NO
	
			# Disable the generation of targets for tests (we don't need them).
			-DLLVM_INCLUDE_TOOLS=OFF
			-DLLVM_INCLUDE_UTILS=OFF
			-DLLVM_INCLUDE_RUNTIMES=OFF
			-DLLVM_INCLUDE_EXAMPLES=OFF
			-DLLVM_INCLUDE_TESTS=OFF
			-DLLVM_INCLUDE_GO_TESTS=OFF
			-DLLVM_INCLUDE_BENCHMARKS=OFF
			-DLLVM_INCLUDE_DOCS=OFF
	
			# Disable build of unnecessary LLVM parts.
			-DLLVM_BUILD_TOOLS=OFF
			-DLLVM_BUILD_UTILS=OFF
			-DLLVM_BUILD_RUNTIMES=OFF
			-DLLVM_BUILD_RUNTIME=OFF
			-DLLVM_BUILD_EXAMPLES=OFF
			-DLLVM_BUILD_TESTS=OFF
			-DLLVM_BUILD_BENCHMARKS=OFF
			-DLLVM_BUILD_DOCS=OFF
			# We don't want this so that we don't have to link with tinfo.
			# It looks like terminal colors are working even without this.
			-DLLVM_ENABLE_TERMINFO=OFF
	
			# Necessary for builds with older MS Visual Studios (e.g. 2015).
			-DLLVM_TEMPORARILY_ALLOW_OLD_TOOLCHAIN=ON
	
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
	
		# Disable the installation right after build (we want to install the
		# needed libraries and tools manually).
		INSTALL_COMMAND ""
	)
	force_configure_step(llvm-project)
else()
	message(STATUS "LLVM: using remote LLVM revision.")

	ExternalProject_Add(llvm-project
		URL https://github.com/avast/llvm/archive/82632c555520b4f490d33c799aa1256817d734d2.zip
		URL_HASH SHA256=634f42177b36d1017ba09a53a9e3a8347cbf388579fa7eaecb9cb0028edeea77
		DOWNLOAD_NAME llvm.zip
		CMAKE_ARGS
			# Force a release build (we don't need to debug LLVM).
			# This has no effect on Windows with MSVC, but is useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			-DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
	
			# Force Python3.
			-DPYTHON_EXECUTABLE=${PYTHON_EXECUTABLE}
	
			# Targets to be build.
			-DLLVM_TARGETS_TO_BUILD=X86
	
			# Our tools depending on LLVM require RTTI, so build LLVM with it.
			-DLLVM_REQUIRES_RTTI=YES
	
			# When building in the debug mode (=> assertions are enabled), we
			# have to build LLVM with assertions. This prevents link errors
			# when building the middle-end and back-end (see
			# https://github.com/oclint/oclint/issues/129).
			-DLLVM_ENABLE_ASSERTIONS=${IS_DEBUG_BUILD}
	
			# Disable the emission of warnings, which are useless since we do
			# not modify the LLVM sources (of course, except for a few
			# exceptions).
			-DLLVM_ENABLE_WARNINGS=NO
	
			# Disable the generation of targets for tests (we don't need them).
			-DLLVM_INCLUDE_TOOLS=OFF
			-DLLVM_INCLUDE_UTILS=OFF
			-DLLVM_INCLUDE_RUNTIMES=OFF
			-DLLVM_INCLUDE_EXAMPLES=OFF
			-DLLVM_INCLUDE_TESTS=OFF
			-DLLVM_INCLUDE_GO_TESTS=OFF
			-DLLVM_INCLUDE_BENCHMARKS=OFF
			-DLLVM_INCLUDE_DOCS=OFF
	
			# Disable build of unnecessary LLVM parts.
			-DLLVM_BUILD_TOOLS=OFF
			-DLLVM_BUILD_UTILS=OFF
			-DLLVM_BUILD_RUNTIMES=OFF
			-DLLVM_BUILD_RUNTIME=OFF
			-DLLVM_BUILD_EXAMPLES=OFF
			-DLLVM_BUILD_TESTS=OFF
			-DLLVM_BUILD_BENCHMARKS=OFF
			-DLLVM_BUILD_DOCS=OFF
			# We don't want this so that we don't have to link with tinfo.
			# It looks like terminal colors are working even without this.
			-DLLVM_ENABLE_TERMINFO=OFF
	
			# Necessary for builds with older MS Visual Studios (e.g. 2015).
			-DLLVM_TEMPORARILY_ALLOW_OLD_TOOLCHAIN=ON
	
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
	
		# Disable the installation right after build (we want to install the
		# needed libraries and tools manually).
		INSTALL_COMMAND ""
	)
endif()

check_if_variable_changed(LLVM_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(llvm-project binary_dir)
	message(STATUS "LLVM: path to LLVM directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

# Add libraries.
ExternalProject_Get_Property(llvm-project binary_dir)

add_library(llvm INTERFACE)
add_dependencies(llvm llvm-project)

set(LLVM_LIB_LIST
	LLVMBitWriter
	LLVMIRReader
	LLVMObject
	LLVMBinaryFormat
	LLVMInstCombine
	LLVMSupport
	LLVMDemangle
	LLVMipo
	LLVMAsmParser
	LLVMBitReader
	LLVMMCParser
	LLVMCodeGen
	LLVMScalarOpts
	LLVMTransformUtils
	LLVMAnalysis
	LLVMTarget
	LLVMCore
	LLVMMC
	LLVMObject
	LLVMPasses
)

if(MSVC)
	set(DEBUG_DIR "Debug/")
	set(RELEASE_DIR "Release/")
endif()

foreach(LLVM_LIB ${LLVM_LIB_LIST})
	target_link_libraries(llvm INTERFACE debug     ${binary_dir}/${DEBUG_DIR}lib/${CMAKE_STATIC_LIBRARY_PREFIX}${LLVM_LIB}${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_link_libraries(llvm INTERFACE optimized ${binary_dir}/${RELEASE_DIR}lib/${CMAKE_STATIC_LIBRARY_PREFIX}${LLVM_LIB}${CMAKE_STATIC_LIBRARY_SUFFIX})
endforeach(LLVM_LIB)

if(CMAKE_THREAD_LIBS_INIT)
	target_link_libraries(llvm INTERFACE debug     ${CMAKE_THREAD_LIBS_INIT})
	target_link_libraries(llvm INTERFACE optimized ${CMAKE_THREAD_LIBS_INIT})
endif()

if(UNIX)
	target_link_libraries(llvm INTERFACE debug     ${ZLIB_LIBRARIES} dl)
	target_link_libraries(llvm INTERFACE optimized ${ZLIB_LIBRARIES} dl)
endif()

# Set include directories.
ExternalProject_Get_Property(llvm-project source_dir)
target_include_directories(llvm SYSTEM INTERFACE ${source_dir}/include)
target_include_directories(llvm SYSTEM INTERFACE ${binary_dir}/include)
