/**
* @file include/llvmir2hll/semantics/semantics/compound_semantics_builder.h
* @brief A class providing an easy construction of compound semantics from
*        several different semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_COMPOUND_SEMANTICS_BUILDER_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_COMPOUND_SEMANTICS_BUILDER_H

#include "llvmir2hll/semantics/semantics/compound_semantics.h"
#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "tl-cpputils/non_copyable.h"

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
class CompoundSemanticsBuilder: private tl_cpputils::NonCopyable {
public:
	static ShPtr<CompoundSemantics> build(const StringVector &semanticsIds);

private:
	// Prevent instantiation.
	CompoundSemanticsBuilder();
};

} // namespace llvmir2hll

#endif
