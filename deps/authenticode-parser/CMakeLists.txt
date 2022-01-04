cmake_minimum_required(VERSION 3.13)

project(authenticode_parser VERSION 1.0.0 LANGUAGES C)

find_package(OpenSSL 1.1.1 REQUIRED)

include(GNUInstallDirs)

add_library(authenticode STATIC
        src/authenticode.c
        src/helper.c
        src/structs.c
        src/countersignature.c
        src/certificate.c
)

add_library(retdec::deps::authenticode ALIAS authenticode)

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
        target_compile_definitions(-DWORDS_BIGENDIAN)
endif()

target_compile_options(authenticode PRIVATE -Wall)
target_compile_features(authenticode PRIVATE c_std_11)

target_include_directories(authenticode
        PUBLIC
                $<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/authenticode-parser/include>
                $<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
        PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(authenticode
        PRIVATE
                OpenSSL::Crypto
)

install(
        DIRECTORY ${RETDEC_DEPS_DIR}/authenticode-parser/include/
        DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

install(TARGETS authenticode
        EXPORT authenticode-targets
        ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

install(EXPORT authenticode-targets
        FILE "retdec-authenticode-targets.cmake"
        NAMESPACE retdec::deps::
        DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

configure_file(
        "retdec-authenticode-config.cmake"
        "${CMAKE_CURRENT_LIST_DIR}/retdec-authenticode-config.cmake"
        @ONLY
)
install(
        FILES "${CMAKE_CURRENT_LIST_DIR}/retdec-authenticode-config.cmake"
        DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)