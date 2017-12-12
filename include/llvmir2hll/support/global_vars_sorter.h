/**
* @file include/llvmir2hll/support/global_vars_sorter.h
* @brief Sorts global variables according to the given conditions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SUPPORT_GLOBAL_VARS_SORTER_H
#define LLVMIR2HLL_SUPPORT_GLOBAL_VARS_SORTER_H

#include "llvmir2hll/support/types.h"

namespace llvmir2hll {

/**
* @brief Sorts global variables according to the given conditions.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class GlobalVarsSorter {
public:
	static GlobalVarDefVector sortByInterdependencies(
		const GlobalVarDefVector &globalVars);
};

} // namespace llvmir2hll

#endif
