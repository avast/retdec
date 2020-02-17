include(ProcessorCount)
include(ExternalProject)

find_package(Threads REQUIRED)

ProcessorCount(CPUS)

set(YARA_DIR          ${CMAKE_CURRENT_BINARY_DIR}/yara/src/yara)
set(YARA_INCLUDE_DIR  ${YARA_DIR}/libyara/include)
set(YARA_LIBRARY_NAME "libyara")

if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(PLATFORM "x64")
        set(YARA_LIBRARY_NAME "${YARA_LIBRARY_NAME}64")
        set(YARAC_NAME "yarac64.exe" CACHE STRING "Yarac binary name" FORCE)
    else()
        set(PLATFORM "x86")
        set(YARA_LIBRARY_NAME "${YARA_LIBRARY_NAME}32")
        set(YARAC_NAME "yarac32.exe" CACHE STRING "Yarac binary name" FORCE)
    endif()

    set(YARA_WIN_DIR       ${YARA_DIR}/windows/vs2015)
    set(YARA_SOLUTION      ${YARA_WIN_DIR}/yara.sln)
    set(YARA_LIBRARY_DIR   ${YARA_WIN_DIR}/libyara/$<CONFIGURATION>)
    set(YARA_BUILD_COMMAND "${CMAKE_VS_MSBUILD_COMMAND}"
        /m:${CPUS}
        /p:Platform=${PLATFORM}
        /p:Configuration=$<CONFIGURATION>
        /p:PlatformToolset=${CMAKE_VS_PLATFORM_TOOLSET}
        /p:WindowsTargetPlatformVersion=${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}
        ${YARA_SOLUTION})
    set(YARAC_PATH         ${YARA_WIN_DIR}/\${CMAKE_INSTALL_CONFIG_NAME}/${YARAC_NAME})
else()
    set(YARA_LIBRARY_DIR ${YARA_DIR}/libyara/.libs)
    set(YARA_BUILD_COMMAND make -j${CPUS})
    set(YARAC_PATH         ${YARA_DIR}/yarac)
endif()

if(YARA_LOCAL_DIR)
    message(STATUS "YARA: using local YARA directory.")

    ExternalProject_Add(yara
        PREFIX "yara"
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${YARA_LOCAL_DIR}"
        DOWNLOAD_NAME yara.zip
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
            ${YARA_BUILD_COMMAND}
        INSTALL_COMMAND ""
    )
    force_configure_step(yara)
else()
    message(STATUS "YARA: using remote YARA revision.")

    ExternalProject_Add(yara
        PREFIX "yara"
        URL ${YARA_URL}
        URL_HASH SHA256=${YARA_ARCHIVE_SHA256}
        DOWNLOAD_NAME yara.zip
        BUILD_IN_SOURCE 1
		# Patch the Yara sources.
		PATCH_COMMAND
			${CMAKE_COMMAND} -Dyara_path=<SOURCE_DIR> -P ${CMAKE_CURRENT_SOURCE_DIR}/patch.cmake
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
            ${YARA_BUILD_COMMAND}
        INSTALL_COMMAND ""
    )
endif()

check_if_variable_changed(YARA_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(yara binary_dir)
	message(STATUS "YARA: path to YARA directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

# https://github.com/avast/retdec/issues/439
if(APPLE)
    execute_process(
        COMMAND xcrun --show-sdk-path
        OUTPUT_VARIABLE MACOS_SDK_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --sysroot=${MACOS_SDK_PATH}")
endif()

if(NOT MSVC)
    ExternalProject_Add_Step(yara configure-linux
        WORKING_DIRECTORY ${YARA_DIR}
        DEPENDEES configure
        DEPENDERS build
        COMMAND ./bootstrap.sh
        COMMAND ./configure
            --prefix=${YARA_INSTALL_DIR}
            --enable-macho
            --disable-shared
            --without-crypto
            CC=${CMAKE_C_COMPILER}
            CFLAGS=${CMAKE_C_FLAGS}
    )
endif()

set(LIBRARIES
    ${YARA_LIBRARY_DIR}/${YARA_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
    ${CMAKE_THREAD_LIBS_INIT}
)

add_library(libyara INTERFACE)
add_dependencies(libyara yara)
set_target_properties(libyara PROPERTIES INTERFACE_LINK_LIBRARIES "${LIBRARIES}")
target_include_directories(libyara INTERFACE ${YARA_INCLUDE_DIR})

# Install yarac application - we may need it to compile YARA files.
install(PROGRAMS "${YARAC_PATH}" DESTINATION bin RENAME "retdec-yarac${CMAKE_EXECUTABLE_SUFFIX}")
