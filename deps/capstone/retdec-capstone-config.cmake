@PACKAGE_INIT@

if(NOT TARGET retdec::capstone-libs)
    add_library(retdec::capstone-libs STATIC IMPORTED)
    set_target_properties(retdec::capstone-libs PROPERTIES
        IMPORTED_LOCATION @PACKAGE_CAPSTONE_LIB_INSTALLED@
    )
endif()

include(${CMAKE_CURRENT_LIST_DIR}/retdec-capstone-targets.cmake)
