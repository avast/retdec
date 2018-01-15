/**
* @file src/llvmir2hll/semantics/semantics/impl_support/get_c_header_file_for_func.cpp
* @brief Implementation of functions from getCHeaderFileForFunc.h.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_c_header_file_for_func.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {

/**
* @brief Returns the header name for the given function from the given map.
*/
Maybe<std::string> getCHeaderFileForFuncFromMap(const std::string &funcName,
		const StringStringUMap &map) {
	auto i = map.find(funcName);
	return i != map.end() ? Just(i->second) : Nothing<std::string>();
}

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
