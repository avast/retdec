include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

set(LIBDWARF_INSTALL_DIR "${PROJECT_BINARY_DIR}/external/src/libdwarf-project-install")

ExternalProject_Add(libdwarf-project
	URL https://github.com/avast-tl/libdwarf/archive/85465d5e235cc2d2f90d04016d6aca1a452d0e73.zip
	URL_HASH SHA256=2864aa7b46529778476190e90359669eb35799ad273233c4df2203bec7db0738
	DOWNLOAD_NAME libdwarf.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DCMAKE_INSTALL_PREFIX=${LIBDWARF_INSTALL_DIR}
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
	# Disable the update step.
	UPDATE_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(libdwarf-project source_dir)
ExternalProject_Get_Property(libdwarf-project binary_dir)

# Add libraries.
add_library(libdwarf INTERFACE)
add_dependencies(libdwarf libdwarf-project)

target_include_directories(libdwarf SYSTEM INTERFACE ${source_dir}/libdwarf)

if(MSVC)
	target_link_libraries(libdwarf INTERFACE ${binary_dir}/libdwarf/libdwarf/$<CONFIGURATION>/${CMAKE_STATIC_LIBRARY_PREFIX}retdec-libdwarf.lib)
	target_link_libraries(libdwarf INTERFACE ${binary_dir}/libelf/lib/$<CONFIGURATION>/${CMAKE_STATIC_LIBRARY_PREFIX}retdec-libelf.lib)
else() # Linux
	target_link_libraries(libdwarf INTERFACE ${LIBDWARF_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}retdec-libdwarf${CMAKE_SHARED_LIBRARY_SUFFIX})
	target_link_libraries(libdwarf INTERFACE ${LIBDWARF_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}retdec-libelf${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if(MSVC)
	install(DIRECTORY "${LIBDWARF_INSTALL_DIR}/bin" DESTINATION "${CMAKE_INSTALL_PREFIX}")
else() # Linux
	install(DIRECTORY "${LIBDWARF_INSTALL_DIR}/lib" DESTINATION "${CMAKE_INSTALL_PREFIX}")
endif()
