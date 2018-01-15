/**
* @file src/llvmir2hll/semantics/semantics/impl_support/get_symbolic_names_for_param.cpp
* @brief Implementation of functions from getSymbolicNamesForParam.h.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_symbolic_names_for_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {

/**
* @brief Returns symbolic names for the given parameter from the given map.
*/
Maybe<IntStringMap> getSymbolicNamesForParamFromMap(const std::string &funcName,
		unsigned paramPos, const FuncParamsMap &map) {
	// Try to find the function.
	auto funcIter = map.find(funcName);
	if (funcIter == map.end()) {
		return Nothing<IntStringMap>();
	}

	// Try to find the parameter by its position.
	auto paramIter = funcIter->second.find(paramPos);
	return paramIter != funcIter->second.end() ?
		Just(paramIter->second) : Nothing<IntStringMap>();
}

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
