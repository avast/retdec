/**
* @file include/llvmir2hll/analysis/goto_target_analysis.h
* @brief Analysis of goto targets.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_ANALYSIS_GOTO_TARGET_ANALYSIS_H
#define LLVMIR2HLL_ANALYSIS_GOTO_TARGET_ANALYSIS_H

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

class Statement;

/**
* @brief Analysis of goto targets.
*
* This class can be used when you want to check whether some statements contain
* goto targets. If you want just a boolean answer (yes/no), use
* hasGotoTargets(). Otherwise, use getGotoTargets() to obtain the set of all
* statements which are goto targets.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class GotoTargetAnalysis: private OrderedAllVisitor,
		private tl_cpputils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~GotoTargetAnalysis() override;

	static StmtSet getGotoTargets(ShPtr<Statement> stmt);
	static bool hasGotoTargets(ShPtr<Statement> stmt);

private:
	GotoTargetAnalysis();

	void putIntoGotoTargetsIfGotoTarget(ShPtr<Statement> stmt);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	virtual void visitStmt(ShPtr<Statement> stmt, bool visitSuccessors = true,
		bool visitNestedStmts = true) override;
	/// @}

private:
	/// All found goto targets.
	StmtSet gotoTargets;
};

} // namespace llvmir2hll

#endif
