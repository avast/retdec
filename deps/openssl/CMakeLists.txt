find_package(Perl REQUIRED)

include(ExternalProject)
include(ProcessorCount)

ProcessorCount(CPUS)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
	set(ARCH_32BIT 1)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(ARCH_64BIT 1)
else()
	message(ERROR "Unsupported architecture. Supported: 32-bit, 64 bit.")
endif()

if(WIN32)
	set(OS_WINDOWS 1)
elseif(UNIX)
	set(OS_LINUX 1)
else()
	message(ERROR "Unsupported system. Supported: Windows, Linux.")
endif()

if(OS_WINDOWS)
	if(MSVC)
		set(COMPILER_MSVC 1)
	else()
		message(ERROR "Unsupported compiler. Supported: MSVC.")
	endif()
else(OS_LINUX)
	if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
		set(COMPILER_GCC 1)
	elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
		set(COMPILER_CLANG 1)
	else()
		message(ERROR "Unsupported compiler. Supported: GCC, Clang.")
	endif()
endif()

if(OS_WINDOWS)
	if(COMPILER_MSVC)
        set(OPENSSL_MAKE "nmake")
		if(ARCH_32BIT)
			set(OPENSSL_CONFIGURE_ARCH "VC-WIN32")
		elseif(ARCH_64BIT)
			set(OPENSSL_CONFIGURE_ARCH "VC-WIN64A")
		endif()
	endif()
elseif(OS_LINUX)
    set(OPENSSL_MAKE make -j${CPUS})
	if(ARCH_32BIT)
		if(COMPILER_GCC)
			set(OPENSSL_CONFIGURE_ARCH "linux-x86")
		else(COMPILER_CLANG)
			set(OPENSSL_CONFIGURE_ARCH "linux-x86-clang")
		endif()
	elseif(ARCH_64BIT)
		if(COMPILER_GCC)
			set(OPENSSL_CONFIGURE_ARCH "linux-x86_64")
		else(COMPILER_CLANG)
			set(OPENSSL_CONFIGURE_ARCH "linux-x86_64-clang")
		endif()
	endif()
endif()

set(OPENSSL_PREFIX         "${CMAKE_CURRENT_BINARY_DIR}/openssl")
set(OPENSSL_SRC_DIR        "${OPENSSL_PREFIX}/src/openssl")
set(OPENSSL_INSTALL_DIR    "${OPENSSL_PREFIX}/src/openssl-install")
set(OPENSSL_VERSION        "1.1.0f")
set(OPENSSL_URL            "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz")
set(OPENSSL_ARCHIVE_SHA256 "12f746f3f2493b2f39da7ecf63d7ee19c6ac9ec6a4fcd8c229da8a522cb12765")

set(OPENSSL_CONFIGURE_OPTIONS
	no-shared
	no-asm
	--prefix=${OPENSSL_INSTALL_DIR}
	--openssldir=${OPENSSL_INSTALL_DIR}
)

if (NOT TARGET openssl)

	ExternalProject_Add(openssl
		PREFIX ${OPENSSL_PREFIX}
		URL ${OPENSSL_URL}
		URL_HASH SHA256=${OPENSSL_ARCHIVE_SHA256}
		CONFIGURE_COMMAND
			${PERL_EXECUTABLE}
			${OPENSSL_SRC_DIR}/Configure
			${OPENSSL_CONFIGURE_OPTIONS}
			${OPENSSL_CONFIGURE_ARCH}
		BUILD_IN_SOURCE 1
		BUILD_COMMAND
			${OPENSSL_MAKE}
		INSTALL_COMMAND
			${OPENSSL_MAKE} install
		LOG_DOWNLOAD 1
		LOG_BUILD 1
		LOG_CONFIGURE 1
		LOG_INSTALL 1
	)

	set(OPENSSL_INCLUDES
		"${OPENSSL_INSTALL_DIR}/include"
		PARENT_SCOPE
	)

	set(OPENSSL_LIBRARIES
		"${OPENSSL_INSTALL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}"
		"${OPENSSL_INSTALL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}"
		PARENT_SCOPE
	)

	add_library(openssl-crypto INTERFACE)
	target_include_directories(openssl-crypto SYSTEM INTERFACE "${OPENSSL_INSTALL_DIR}/include")
	target_link_libraries(openssl-crypto INTERFACE "${OPENSSL_INSTALL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}")
	if(MSVC)
		target_link_libraries(openssl-crypto INTERFACE ws2_32 gdi32 advapi32 crypt32 user32)
	endif()
	add_dependencies(openssl-crypto openssl)

endif()
