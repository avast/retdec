
if(NOT TARGET retdec::llvmir2hll)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            config
            utils
            rapidjson
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvmir2hll-targets.cmake)
endif()
