

foreach(component ${retdec_FIND_COMPONENTS})
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-${component}-config.cmake)
endforeach()
