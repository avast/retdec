/**
* @file include/llvmir2hll/semantics/semantics/win_api_semantics/func_never_returns.h
* @brief Provides function funcNeverReturns() for WinAPISemantics in the
*        semantics::win_api namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_FUNC_NEVER_RETURNS_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_FUNC_NEVER_RETURNS_H

#include <string>

#include "llvmir2hll/support/maybe.h"

namespace llvmir2hll {
namespace semantics {
namespace win_api {

Maybe<bool> funcNeverReturns(const std::string &funcName);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll

#endif
