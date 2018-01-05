/**
* @file include/retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_param.h
* @brief Provides function getNameOfParam() for GCCGeneralSemantics in the
*        semantics::gcc_general namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_NAME_OF_PARAM_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_GCC_GENERAL_SEMANTICS_GET_NAME_OF_PARAM_H

#include <string>

#include "retdec/llvmir2hll/support/maybe.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

Maybe<std::string> getNameOfParam(const std::string &funcName,
	unsigned paramPos);

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
