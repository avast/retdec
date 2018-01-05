/**
* @file include/retdec/llvmir2hll/analysis/break_in_if_analysis.h
* @brief Analysis of a break statement in an if statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_BREAK_IN_IF_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_BREAK_IN_IF_ANALYSIS_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
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
		private retdec::utils::NonCopyable {
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
} // namespace retdec

#endif
