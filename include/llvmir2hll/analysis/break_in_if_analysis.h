/**
* @file include/llvmir2hll/analysis/break_in_if_analysis.h
* @brief Analysis of a break statement in an if statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_ANALYSIS_BREAK_IN_IF_ANALYSIS_H
#define LLVMIR2HLL_ANALYSIS_BREAK_IN_IF_ANALYSIS_H

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

class Statement;

/**
* @brief Analysis of a break statement in an if statement.
*
* This class can be used when you want to check whether an if statement
* contains a break statement.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class BreakInIfAnalysis: private OrderedAllVisitor,
		private tl_cpputils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~BreakInIfAnalysis() override;

	static bool hasBreakStmt(ShPtr<IfStmt> stmt);

private:
	BreakInIfAnalysis();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	/// @}

private:
	/// If break statement was found.
	bool foundBreakStmt;
};

} // namespace llvmir2hll

#endif
