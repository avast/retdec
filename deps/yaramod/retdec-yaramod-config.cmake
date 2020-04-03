@PACKAGE_INIT@

if(NOT TARGET yaramod-libs)
    add_library(yaramod-libs INTERFACE)
    add_library(retdec::deps::yaramod-libs ALIAS yaramod-libs)
    foreach(YARAMOD_LIB @PACKAGE_YARAMOD_LIBS_INSTALLED@)
        target_link_libraries(yaramod-libs INTERFACE
            ${YARAMOD_LIB}
        )
    endforeach(YARAMOD_LIB)
endif()

if(NOT TARGET retdec::deps::yaramod)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-yaramod-targets.cmake)
endif()
