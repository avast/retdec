/**
* @file include/retdec/llvmir2hll/analysis/null_pointer_analysis.h
* @brief Analysis of the use of null pointers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_NULL_POINTER_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_NULL_POINTER_ANALYSIS_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief Analysis of the use of null pointers.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class NullPointerAnalysis: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~NullPointerAnalysis() override;

	static bool useNullPointers(ShPtr<Module> module);

private:
	NullPointerAnalysis(ShPtr<Module> module);

	void analyzeNullPointersUsage();
	void analyzeAllGlobalVariables();
	void analyzeAllFunctions();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ConstNullPointer> constant) override;
	/// @}

private:
	/// The module to be checked.
	ShPtr<Module> module;

	/// Has the null pointer been found?
	bool foundNullPointer;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
