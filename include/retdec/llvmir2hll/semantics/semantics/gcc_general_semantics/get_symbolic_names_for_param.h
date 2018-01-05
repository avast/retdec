/**
* @file include/retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_symbolic_names_for_param.h
* @brief Provides function getSymbolicNamesForParam() for
*        GCCGeneralSemantics in the semantics::gcc_general namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_SYMBOLIC_NAMES_FOR_PARAM_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_SYMBOLIC_NAMES_FOR_PARAM_H

#include <string>

#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

Maybe<IntStringMap> getSymbolicNamesForParam(const std::string &funcName,
	unsigned paramPos);

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
