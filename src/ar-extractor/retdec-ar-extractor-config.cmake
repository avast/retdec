
if(NOT TARGET retdec::ar-extractor)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            utils
            llvm
            rapidjson
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ar-extractor-targets.cmake)
endif()
