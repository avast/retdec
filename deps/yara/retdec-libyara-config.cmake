@PACKAGE_INIT@

if(NOT TARGET retdec::deps::libyara-libs)
    add_library(retdec::deps::libyara-libs STATIC IMPORTED)
    set_target_properties(retdec::deps::libyara-libs PROPERTIES
        IMPORTED_LOCATION @PACKAGE_LIBYARA_LIBRARY@
    )
endif()

if(NOT TARGET retdec::deps::libyara)
    find_package(Threads REQUIRED)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-libyara-targets.cmake)
endif()
