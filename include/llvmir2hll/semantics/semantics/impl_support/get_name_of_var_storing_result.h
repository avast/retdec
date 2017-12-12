/**
* @file include/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.h
* @brief Support for implementing the getNameOfVarStoringResult semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_NAME_OF_VAR_STORING_RESULT_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_NAME_OF_VAR_STORING_RESULT_H

#include "llvmir2hll/support/maybe.h"
#include "llvmir2hll/support/types.h"

namespace llvmir2hll {
namespace semantics {

Maybe<std::string> getNameOfVarStoringResultFromMap(
	const std::string &funcName, const StringStringUMap &map);

} // namespace semantics
} // namespace llvmir2hll

#endif
