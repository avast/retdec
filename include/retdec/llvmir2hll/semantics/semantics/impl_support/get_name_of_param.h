/**
* @file include/retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h
* @brief Support for implementing the getNameOfParam semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_NAME_OF_PARAM_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_NAME_OF_PARAM_H

#include <cstddef>
#include <string>
#include <unordered_map>

#include "retdec/llvmir2hll/support/maybe.h"

/**
* @brief Sets a name of the given parameter for the given function.
*/
#define ADD_PARAM_NAME(funcName, paramPos, paramName) \
	funcParamNamesMap[FuncParamPosPair(funcName, paramPos)] = paramName;

namespace retdec {
namespace llvmir2hll {
namespace semantics {

/// A pair of function name and parameter position.
using FuncParamPosPair = std::pair<std::string, unsigned>;

/**
* @brief A hashing functor for FuncParamPosPair.
*/
struct FuncParamPosPairHasher {
	std::size_t operator()(const FuncParamPosPair &p) const {
		return std::hash<std::string>()(p.first) + p.second;
	}
};

/// Mapping of a function name and parameter position into the name of this
/// parameter.
using FuncParamNamesMap = std::unordered_map<FuncParamPosPair, std::string,
	FuncParamPosPairHasher>;

Maybe<std::string> getNameOfParamFromMap(const std::string &funcName,
	unsigned paramPos, const FuncParamNamesMap &map);

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
