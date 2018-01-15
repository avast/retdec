/**
* @file include/retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.h
* @brief Support for implementing the getNameOfVarStoringResult semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_NAME_OF_VAR_STORING_RESULT_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_NAME_OF_VAR_STORING_RESULT_H

#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {

Maybe<std::string> getNameOfVarStoringResultFromMap(
	const std::string &funcName, const StringStringUMap &map);

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
