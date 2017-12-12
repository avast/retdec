/**
* @file include/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_var_storing_result.h
* @brief Provides function getNameOfVarStoringResult() for
*        GCCGeneralSemantics in the semantics::gcc_general namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H

#include <string>

#include "llvmir2hll/support/maybe.h"

namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

Maybe<std::string> getNameOfVarStoringResult(const std::string &funcName);

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll

#endif
