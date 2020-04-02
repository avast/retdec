@PACKAGE_INIT@

add_library(retdec::capstone-libs STATIC IMPORTED)
set_target_properties(retdec::capstone-libs PROPERTIES
    IMPORTED_LOCATION @PACKAGE_CAPSTONE_LIB_INSTALLED@
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-capstone-targets.cmake)
