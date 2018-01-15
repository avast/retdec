/**
* @file src/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.cpp
* @brief Implementation of functions from getNameOfVarStoringResult.h.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {

/**
* @brief Returns the name of a variable storing the result from the given
*        function from the given map.
*/
Maybe<std::string> getNameOfVarStoringResultFromMap(const std::string &funcName,
		const StringStringUMap &map) {
	auto i = map.find(funcName);
	return i != map.end() ? Just(i->second) : Nothing<std::string>();
}

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
