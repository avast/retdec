/**
* @file include/llvmir2hll/support/struct_types_sorter.h
* @brief Sorts structured types according to their names and dependencies.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SUPPORT_STRUCT_TYPES_SORTER_H
#define LLVMIR2HLL_SUPPORT_STRUCT_TYPES_SORTER_H

#include <vector>

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

/**
* @brief Sorts structured types according to their names and dependencies.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class StructTypesSorter: private tl_cpputils::NonCopyable {
public:
	static StructTypeVector sort(const StructTypeSet &types);
};

} // namespace llvmir2hll

#endif
