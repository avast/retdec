/**
* @file include/llvmir2hll/semantics/semantics/win_api_semantics/get_c_header_file_for_func.h
* @brief Provides function getCHeaderFileForFunc() for
*        WinAPISemantics in the semantics::win_api namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_C_HEADER_FILE_FOR_FUNC_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_C_HEADER_FILE_FOR_FUNC_H

#include <string>

#include "llvmir2hll/support/maybe.h"

namespace llvmir2hll {
namespace semantics {
namespace win_api {

Maybe<std::string> getCHeaderFileForFunc(const std::string &funcName);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll

#endif
