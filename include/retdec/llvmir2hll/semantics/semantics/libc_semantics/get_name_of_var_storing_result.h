/**
* @file include/retdec/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_var_storing_result.h
* @brief Provides function getNameOfVarStoringResult() for
*        LibcSemantics in the semantics::libc namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_LIBC_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_LIBC_SEMANTICS_GET_NAME_OF_VAR_STORING_RESULT_H

#include <optional>
#include <string>

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace libc {

std::optional<std::string> getNameOfVarStoringResult(const std::string &funcName);

} // namespace libc
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
