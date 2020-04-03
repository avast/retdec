

foreach(component ${retdec_FIND_COMPONENTS})
    if(NOT TARGET retdec::${component})
        include(${CMAKE_CURRENT_LIST_DIR}/retdec-${component}-config.cmake)
    endif()
endforeach()
