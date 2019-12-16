/**
* @file src/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.cpp
* @brief Implementation of functions from getNameOfParam.h.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {

/**
* @brief Returns the name of the given parameter from the given map.
*/
std::optional<std::string> getNameOfParamFromMap(const std::string &funcName,
		unsigned paramPos, const FuncParamNamesMap &map) {
	auto funcParamIter = map.find(FuncParamPosPair(funcName, paramPos));
	return funcParamIter != map.end() ?
		std::optional<std::string>(funcParamIter->second) : std::nullopt;
}

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
