@PACKAGE_INIT@

if(NOT TARGET retdec::deps::capstone-libs)
    add_library(retdec::deps::capstone-libs STATIC IMPORTED)
    set_target_properties(retdec::deps::capstone-libs PROPERTIES
        IMPORTED_LOCATION @PACKAGE_CAPSTONE_LIB_INSTALLED@
    )
endif()

if(NOT TARGET retdec::deps::capstone)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-capstone-targets.cmake)
endif()
