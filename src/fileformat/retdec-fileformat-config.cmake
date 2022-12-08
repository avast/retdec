
if(NOT TARGET retdec::fileformat)
    if(WIN32)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
        set(OPENSSL_MSVC_STATIC_RT @RETDEC_MSVC_STATIC_RUNTIME@)
    endif()
    find_package(OpenSSL 1.0.1 REQUIRED)

    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            common
            utils
            pelib
            elfio
            llvm
            tlsh
            stb
            authenticode
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-fileformat-targets.cmake)
endif()
