
# capstone2llvmir
set(CAPSTONE2LLVMIR_TOOLS ON CACHE BOOL "enable capstone2llvmir" FORCE)
set(CAPSTONE2LLVMIR_TESTS ${DEPS_TESTS} CACHE BOOL "enable capstone2llvmir tests" FORCE)

# csim
set(CLANG_DIR "${RETDEC_DEV_SUPPORT_DIR}/clang")
set(CSIM_TOOLS ON CACHE BOOL "enable csim" FORCE)
set(CSIM_TESTS ${DEPS_TESTS} CACHE BOOL "enable csim tests" FORCE)

# ctypes
set(CTYPES_TESTS ${DEPS_TESTS} CACHE BOOL "enable ctypes tests" FORCE)

# demangler
set(DEMANGLER_TOOLS OFF CACHE BOOL "enable demangler tools" FORCE)
set(DEMANGLER_TESTS ${DEPS_TESTS} CACHE BOOL "enable demangler tests" FORCE)

# fileformat
set(FILEFORMAT_TESTS ${DEPS_TESTS} CACHE BOOL "enable fileformat tests" FORCE)

# libdwarf
set(LIBDWARF_INSTALL_TO_UNITTESTS ${RETDEC_TESTS} CACHE BOOL "enable libdwarf installation to unit tests directory" FORCE)

# retdec-config
set(RETDEC_CONFIG_TOOLS ON CACHE BOOL "enable retdec-config tools" FORCE)
set(RETDEC_CONFIG_TESTS ${DEPS_TESTS} CACHE BOOL "enable retdec-config tests" FORCE)

# tl-cpputils
set(TL_CPPUTILS_TESTS ${DEPS_TESTS} CACHE BOOL "enable tl-cpputils tests" FORCE)

# yaramod
set(YARAMOD_TESTS ${DEPS_TESTS} CACHE BOOL "enable yaramod tests" FORCE)
