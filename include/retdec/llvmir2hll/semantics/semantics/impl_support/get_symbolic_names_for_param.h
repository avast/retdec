/**
* @file include/retdec/llvmir2hll/semantics/semantics/impl_support/get_symbolic_names_for_param.h
* @brief Support for implementing the getSymbolicNamesForParam semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_SYMBOLIC_NAMES_FOR_PARAM_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_IMPL_SUPPORT_GET_SYMBOLIC_NAMES_FOR_PARAM_H

#include <map>
#include <unordered_map>

#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"

/**
* @brief Starts a definition of a getSymbolicNamesFor() function.
*
* Such a function can be used to provide the creation of @c symbolicNamesMap
* for a specific set of names, like signal numbers or error numbers. In this
* way, the names can be aggregated on a single place and not copy&pasted to
* every place they are needed (@c error(), @c error_at_line(), etc).
*
* The created function ensures that the map is filled at most once (upon the
* first call). Therefore, when you call the function for the second time, the
* already filled map is returned without filling the map again with the same
* data.
*
* @par Important Note
*
* Every use of this macro has to be ended with
* DEFINE_GET_SYMBOLIC_NAMES_FUNC_END.
*
* @par Usage Example
* @code
* DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(getSymbolicNamesForSignalHandlers)
*     // Info from: <sys/signal.h>
*     symbolicNamesMap[0] = "SIG_DFL";
*     symbolicNamesMap[1] = "SIG_IGN";
* DEFINE_GET_SYMBOLIC_NAMES_FUNC_END()
*
* // ...
*
* paramSymbolsMap[2] = getSymbolicNamesForSignalHandlers();
* @endcode
*/
#define DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN(funcName) \
	const IntStringMap &funcName() { \
		static IntStringMap symbolicNamesMap; \
		if (!symbolicNamesMap.empty()) { \
			return symbolicNamesMap; \
		}

/**
* @brief The ending part of DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN.
*
* @see DEFINE_GET_SYMBOLIC_NAMES_FUNC_BEGIN
*/
#define DEFINE_GET_SYMBOLIC_NAMES_FUNC_END() \
		return symbolicNamesMap; \
	}

namespace retdec {
namespace llvmir2hll {
namespace semantics {

/// Mapping of a parameter position into symbolic names of its possible values.
using ParamSymbolsMap = std::map<unsigned, IntStringMap>;

/// Mapping of a function name into ParamSymbolsMap.
using FuncParamsMap = std::unordered_map<std::string, ParamSymbolsMap>;

Maybe<IntStringMap> getSymbolicNamesForParamFromMap(const std::string &funcName,
	unsigned paramPos, const FuncParamsMap &map);

} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
