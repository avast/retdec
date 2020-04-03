@PACKAGE_INIT@

if(NOT TARGET retdec::libyara-libs)
    add_library(retdec::libyara-libs STATIC IMPORTED)
    set_target_properties(retdec::libyara-libs PROPERTIES
        IMPORTED_LOCATION @PACKAGE_LIBYARA_LIBRARY@
    )
endif()

if(NOT TARGET retdec::libyara)
    find_package(Threads REQUIRED)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-libyara-targets.cmake)
endif()
