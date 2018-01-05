
cmake_minimum_required(VERSION 3.6)

include(ExternalProject)

set(LIBDWARF_INSTALL_DIR "${PROJECT_BINARY_DIR}/external/libdwarf-project-install")

ExternalProject_Add(libdwarf-project
	URL https://github.com/avast-tl/libdwarf/archive/93754e7e12d858f94ff9b2339f3206e54cfbda27.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DCMAKE_INSTALL_PREFIX=${LIBDWARF_INSTALL_DIR}
		-DLIBDWARF_INSTALL_TO_UNITTESTS=${RETDEC_TESTS}
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
	target_link_libraries(libdwarf INTERFACE ${binary_dir}/libdwarf/libdwarf/$<CONFIGURATION>/${CMAKE_FIND_LIBRARY_PREFIXES}retdec-libdwarf.lib)
	target_link_libraries(libdwarf INTERFACE ${binary_dir}/libelf/lib/$<CONFIGURATION>/${CMAKE_FIND_LIBRARY_PREFIXES}retdec-libelf.lib)
else() # Linux
	target_link_libraries(libdwarf INTERFACE ${LIBDWARF_INSTALL_DIR}/lib/${CMAKE_FIND_LIBRARY_PREFIXES}retdec-libdwarf${CMAKE_SHARED_LIBRARY_SUFFIX})
	target_link_libraries(libdwarf INTERFACE ${LIBDWARF_INSTALL_DIR}/lib/${CMAKE_FIND_LIBRARY_PREFIXES}retdec-libelf${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if(MSVC)
	install(DIRECTORY "${LIBDWARF_INSTALL_DIR}/bin" DESTINATION "${CMAKE_INSTALL_PREFIX}")
else() # Linux
	install(DIRECTORY "${LIBDWARF_INSTALL_DIR}/lib" DESTINATION "${CMAKE_INSTALL_PREFIX}")
endif()
