/**
* @file include/retdec/llvmir2hll/semantics/semantics/win_api_semantics/func_never_returns.h
* @brief Provides function funcNeverReturns() for WinAPISemantics in the
*        semantics::win_api namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_FUNC_NEVER_RETURNS_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_FUNC_NEVER_RETURNS_H

#include <string>

#include "retdec/llvmir2hll/support/maybe.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

Maybe<bool> funcNeverReturns(const std::string &funcName);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
