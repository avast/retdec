/**
* @file include/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_var_storing_result.h
* @brief Provides function getNameOfVarStoringResult() for
*        WinAPISemantics in the semantics::win_api namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H

#include <string>

#include "llvmir2hll/support/maybe.h"

namespace llvmir2hll {
namespace semantics {
namespace win_api {

Maybe<std::string> getNameOfVarStoringResult(const std::string &funcName);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll

#endif
