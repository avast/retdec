cmake_minimum_required(VERSION 3.13)

project(stb VERSION 1.0.0 LANGUAGES C)

add_library(stb STATIC
        stb_image.c
)

add_library(retdec::deps::stb ALIAS stb)

target_include_directories(stb
        PUBLIC
                $<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/stb/include>
                $<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
        PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}
)

install(
        DIRECTORY ${RETDEC_DEPS_DIR}/stb/include/
        DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

install(TARGETS stb
        EXPORT stb-targets
        ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

install(EXPORT stb-targets
        FILE "retdec-stb-targets.cmake"
        NAMESPACE retdec::deps::
        DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

configure_file(
        "retdec-stb-config.cmake"
        "${CMAKE_CURRENT_LIST_DIR}/retdec-stb-config.cmake"
        @ONLY
)
install(
        FILES "${CMAKE_CURRENT_LIST_DIR}/retdec-stb-config.cmake"
        DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)