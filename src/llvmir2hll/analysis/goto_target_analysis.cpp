/**
* @file src/llvmir2hll/analysis/goto_target_analysis.cpp
* @brief Implementation of GotoTargetAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/goto_target_analysis.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new analysis.
*/
GotoTargetAnalysis::GotoTargetAnalysis():
	OrderedAllVisitor(), gotoTargets() {}

/**
* @brief Destructs the analysis.
*/
GotoTargetAnalysis::~GotoTargetAnalysis() {}

/*
* @brief Returns the set of all goto targets reachable from the given
*        statement.
*
* @param[in] stmt Statement where the search is to be started.
*
* @par Preconditions
*  - @a stmt is non-null
*/
StmtSet GotoTargetAnalysis::getGotoTargets(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	ShPtr<GotoTargetAnalysis> analysis(new GotoTargetAnalysis());
	analysis->visitStmt(stmt);
	return analysis->gotoTargets;
}

/**
* @brief Returns @c true if there are goto targets reachable from the given
*        statement, @c false otherwise.
*
* @param[in] stmt Statement where the search is to be started.
*
* @par Preconditions
*  - @a stmt is non-null
*/
bool GotoTargetAnalysis::hasGotoTargets(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	ShPtr<GotoTargetAnalysis> analysis(new GotoTargetAnalysis());
	analysis->visitStmt(stmt);
	return !analysis->gotoTargets.empty();
}

/**
* @brief Checks whether the given statement is a goto target, and if so, puts
*        it into @c gotoTargets.
*/
void GotoTargetAnalysis::putIntoGotoTargetsIfGotoTarget(ShPtr<Statement> stmt) {
	if (stmt && stmt->isGotoTarget()) {
		gotoTargets.insert(stmt);
	}
}

void GotoTargetAnalysis::visit(ShPtr<GotoStmt> stmt) {
	// Do not visit the goto's target, just its successor (if any).
	visitStmt(stmt->getSuccessor());
}

void GotoTargetAnalysis::visitStmt(ShPtr<Statement> stmt, bool visitSuccessors,
		bool visitNestedStmts) {
	putIntoGotoTargetsIfGotoTarget(stmt);
	OrderedAllVisitor::visitStmt(stmt, visitSuccessors, visitNestedStmts);
}

} // namespace llvmir2hll
} // namespace retdec
