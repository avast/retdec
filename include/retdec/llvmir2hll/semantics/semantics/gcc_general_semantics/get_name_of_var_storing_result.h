/**
* @file include/retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_var_storing_result.h
* @brief Provides function getNameOfVarStoringResult() for
*        GCCGeneralSemantics in the semantics::gcc_general namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H

#include <optional>
#include <string>

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

std::optional<std::string> getNameOfVarStoringResult(const std::string &funcName);

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
