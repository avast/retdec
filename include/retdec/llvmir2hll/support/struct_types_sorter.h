/**
* @file include/retdec/llvmir2hll/support/struct_types_sorter.h
* @brief Sorts structured types according to their names and dependencies.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_STRUCT_TYPES_SORTER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_STRUCT_TYPES_SORTER_H

#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Sorts structured types according to their names and dependencies.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class StructTypesSorter: private retdec::utils::NonCopyable {
public:
	static StructTypeVector sort(const StructTypeSet &types);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
