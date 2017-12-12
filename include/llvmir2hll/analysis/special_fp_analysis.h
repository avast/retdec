/**
* @file include/llvmir2hll/analysis/special_fp_analysis.h
* @brief A visitor for obtaining information whether a special floating-point
*        value is used in a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_ANALYSIS_SPECIAL_FP_ANALYSIS_H
#define LLVMIR2HLL_ANALYSIS_SPECIAL_FP_ANALYSIS_H

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

class ConstFloat;
class Module;

/**
* @brief A visitor for obtaining information whether a special floating-point
*        value is used in a module.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class SpecialFPAnalysis: private OrderedAllVisitor,
		private tl_cpputils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~SpecialFPAnalysis() override;

	static bool hasSpecialFP(ShPtr<Module> module);

private:
	explicit SpecialFPAnalysis();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ConstFloat> constant) override;
	/// @}

private:
	/// Is a special floating-point value used in the module?
	bool specialFPFound;
};

} // namespace llvmir2hll

#endif
