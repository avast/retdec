/**
* @file include/retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_c_header_file_for_func.h
* @brief Provides function getCHeaderFileForFunc() for
*        GCCGeneralSemantics in the semantics::gcc_general namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_C_HEADER_FILE_FOR_FUNC_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_C_HEADER_FILE_FOR_FUNC_H

#include <string>

#include "retdec/llvmir2hll/support/maybe.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

Maybe<std::string> getCHeaderFileForFunc(const std::string &funcName);

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
