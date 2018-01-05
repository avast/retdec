/**
* @file include/retdec/llvmir2hll/semantics/semantics/compound_semantics_builder.h
* @brief A class providing an easy construction of compound semantics from
*        several different semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_COMPOUND_SEMANTICS_BUILDER_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_COMPOUND_SEMANTICS_BUILDER_H

#include "retdec/llvmir2hll/semantics/semantics/compound_semantics.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A class providing an easy construction of compound semantics from
*        several different semantics.
*
* To build compound semantics, use build().
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class CompoundSemanticsBuilder: private retdec::utils::NonCopyable {
public:
	static ShPtr<CompoundSemantics> build(const StringVector &semanticsIds);

private:
	// Prevent instantiation.
	CompoundSemanticsBuilder();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
