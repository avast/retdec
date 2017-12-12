/**
* @file include/llvmir2hll/semantics/semantics/gcc_general_semantics/get_c_header_file_for_func.h
* @brief Provides function getCHeaderFileForFunc() for
*        GCCGeneralSemantics in the semantics::gcc_general namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_C_HEADER_FILE_FOR_FUNC_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_C_HEADER_FILE_FOR_FUNC_H

#include <string>

#include "llvmir2hll/support/maybe.h"

namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

Maybe<std::string> getCHeaderFileForFunc(const std::string &funcName);

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll

#endif
