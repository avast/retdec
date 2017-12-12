/**
* @file include/llvmir2hll/semantics/semantics/win_api_semantics/get_symbolic_names_for_param.h
* @brief Provides function getSymbolicNamesForParam() for WinAPISemantics in the
*        semantics::win_api namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_SYMBOLIC_NAMES_FOR_PARAM_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_SYMBOLIC_NAMES_FOR_PARAM_H

#include <string>

#include "llvmir2hll/support/maybe.h"
#include "llvmir2hll/support/types.h"

namespace llvmir2hll {
namespace semantics {
namespace win_api {

Maybe<IntStringMap> getSymbolicNamesForParam(const std::string &funcName,
	unsigned paramPos);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll

#endif
