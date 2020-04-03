
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        utils
        rapidjson
        llvm
)

if(NOT TARGET retdec::macho-extractor)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-macho-extractor-targets.cmake)
endif()
