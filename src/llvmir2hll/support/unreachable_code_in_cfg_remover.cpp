/**
* @file src/llvmir2hll/support/unreachable_code_in_cfg_remover.cpp
* @brief Implementation of UnreachableCodeInCFGRemover.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/goto_target_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/unreachable_code_in_cfg_remover.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new remover.
*
* See removeCode() for the description of all parameters and preconditions.
*/
UnreachableCodeInCFGRemover::UnreachableCodeInCFGRemover(ShPtr<Module> module):
	module(module), cfg(), cfgBuilder(NonRecursiveCFGBuilder::create()) {}

/**
* @brief Destructs the remover.
*/
UnreachableCodeInCFGRemover::~UnreachableCodeInCFGRemover() {}

/**
* @brief Removes code from all the functions in @a module that is unreachable
*        in the CFG.
*
* @param[in,out] module Module in which the code is to be removed.
*
* For example, the last return in the following piece of code can be removed:
* @code
* void test() {
*     if (1) {
*         return 1;
*     } else {
*         return 2;
*     }
*     return 0;       <-- to be removed
* }
* @endcode
*
* Empty statements which had successors that were removed are also removed.
* Otherwise, they are kept untouched.
*
* @par Preconditions
*  - @a module is non-null
*/
void UnreachableCodeInCFGRemover::removeCode(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	ShPtr<UnreachableCodeInCFGRemover> remover(new UnreachableCodeInCFGRemover(
		module));
	remover->performRemoval();
}

/**
* @brief Performs the removal of code.
*
* For more information, see the description of removeCode().
*/
void UnreachableCodeInCFGRemover::performRemoval() {
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		performRemovalInFunc(*i);
	}
}

/**
* @brief Performs the removal of code in the given function.
*/
void UnreachableCodeInCFGRemover::performRemovalInFunc(ShPtr<Function> func) {
	cfg = cfgBuilder->getCFG(func);

	ShPtr<Statement> body(func->getBody());
	if (!skipEmptyStmts(body)) {
		// The body is empty.
		return;
	}
	visitStmt(body);
}

void UnreachableCodeInCFGRemover::visitStmt(ShPtr<Statement> stmt,
		bool visitSuccessors, bool visitNestedStmts) {
	if (!stmt || hasItem(accessedStmts, stmt)) {
		return;
	}

	// Do not remove statements that are goto targets. Otherwise, we might end
	// up with goto statements without targets.
	// TODO Can we relax this restriction a bit?
	if (stmt->isGotoTarget()) {
		return;
	}

	// We have to keep the information whether the statement had a successor
	// before calling visitStmt(). The reason is that after the call, it may no
	// longer have a successor.
	bool stmtHadSuccessor(stmt->hasSuccessor());
	OrderedAllVisitor::visitStmt(stmt, visitSuccessors, visitNestedStmts);

	// Empty statements do not appear in CFGs, so we have to treat them in a
	// special way.
	if (isa<EmptyStmt>(stmt)) {
		// We remove the statement only if it has lost its successor.
		if (stmtHadSuccessor && !stmt->hasSuccessor()) {
			Statement::removeStatement(stmt);
			cfg->removeStmt(stmt);
		}
		return;
	}

	if (cfg->hasNodeForStmt(stmt)) {
		// The statement is reachable in the CFG.
		return;
	}

	if (stmt->isCompound() && GotoTargetAnalysis::hasGotoTargets(stmt)) {
		// It is a compound statement leading to some goto target. We need to
		// preserve such a statement.
		return;
	}

	Statement::removeStatement(stmt);
	cfg->removeStmt(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
