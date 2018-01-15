/**
* @file src/llvmir2hll/analysis/break_in_if_analysis.cpp
* @brief Implementation of BreakInIfAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/break_in_if_analysis.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new analysis.
*/
BreakInIfAnalysis::BreakInIfAnalysis():
	OrderedAllVisitor(), foundBreakStmt(false) {}

/**
* @brief Destructs the analysis.
*/
BreakInIfAnalysis::~BreakInIfAnalysis() {}

/**
* @brief Returns @c true if there is at least one break statement in the given
*        if statement, @c false otherwise.
*
* BreakStmt is also searched in all nested statements in the given statement.
*
* @param[in] stmt If statement where the search is started.
*
* @par Preconditions
*  - @a stmt is non-null
*/
bool BreakInIfAnalysis::hasBreakStmt(ShPtr<IfStmt> stmt) {
	PRECONDITION_NON_NULL(stmt);

	ShPtr<BreakInIfAnalysis> analysis(new BreakInIfAnalysis());

	// Can't be substituted this block to stmt->accept(analysis.get()) because
	// we want to find break statements only in if statement body.
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		analysis->visitStmt(i->second);
	}
	analysis->visitStmt(stmt->getElseClause());

	return analysis->foundBreakStmt;
}

void BreakInIfAnalysis::visit(ShPtr<BreakStmt> stmt) {
	foundBreakStmt |= true;
}

void BreakInIfAnalysis::visit(ShPtr<GotoStmt> stmt) {
	// Do not visit the goto's target, just its successor (if any).
	// We don't want to find break statement that is out of if statement body.
	OrderedAllVisitor::visitStmt(stmt->getSuccessor());
}

} // namespace llvmir2hll
} // namespace retdec
