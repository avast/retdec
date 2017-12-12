/**
* @file include/llvmir2hll/semantics/semantics/impl_support/get_c_header_file_for_func.h
* @brief Support for implementing the getCHeaderFileForFunc semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_C_HEADER_FILE_FOR_FUNC_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_C_HEADER_FILE_FOR_FUNC_H

#include <cstddef>

#include "llvmir2hll/support/maybe.h"
#include "llvmir2hll/support/types.h"
#include "tl-cpputils/array.h"

/**
* @brief Maps all the functions from array @a funcs into @a header by adding
*        them into @a map.
*
* @param[in] funcs Statically allocated array of function names
*                  (<tt>const char *</tt>).
* @param[in] header The name of the header file (<tt>const char *</tt>).
* @param[out] map A map into which the mappings will be stored.
*/
#define ADD_FUNCS_TO_C_HEADER_MAP(funcs, header, map) \
	for (std::size_t i = 0, e = tl_cpputils::arraySize(funcs); i != e; ++i) { \
		map[funcs[i]] = header; \
	}

namespace llvmir2hll {
namespace semantics {

Maybe<std::string> getCHeaderFileForFuncFromMap(const std::string &funcName,
		const StringStringUMap &map);

} // namespace semantics
} // namespace llvmir2hll

#endif
