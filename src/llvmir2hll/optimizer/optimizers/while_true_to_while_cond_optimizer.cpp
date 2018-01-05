/**
* @file src/llvmir2hll/optimizer/optimizers/while_true_to_while_cond_optimizer.cpp
* @brief Implementation of WhileTrueToWhileCondOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_while_cond_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
WhileTrueToWhileCondOptimizer::WhileTrueToWhileCondOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
WhileTrueToWhileCondOptimizer::~WhileTrueToWhileCondOptimizer() {}

void WhileTrueToWhileCondOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Ignore while loops where the condition is not the constant "true".
	if (!isWhileTrueLoop(stmt)) {
		return;
	}

	// Ignore while loops that are goto targets because the optimization
	// currently does not work in such cases (it looses the connection between
	// gotos and the original target due to body duplication).
	// TODO Can we support also optimization of such loops?
	if (stmt->isGotoTarget()) {
		return;
	}

	// Gather all information needed to transform the loop.
	ShPtr<SplittedWhileTrueLoop> splittedLoop(splitWhileTrueLoop(stmt));
	if (!splittedLoop) {
		// The loop cannot be optimized.
		return;
	}

	// The transformation is done in the following steps:
	//
	// We switch the old condition with the new one (notice that we have to
	// negate it).
	stmt->setCondition(ExpressionNegater::negate(
		splittedLoop->loopEnd->getFirstIfCond()));

	// If the predecessor of the original loop is an empty statement,
	// remove it and store it for later use (it usually contains a debug
	// comment). This way, instead of e.g.
	//
	// # branch -> bb
	// dest[i] = src[i]
	// while (src[i] != 0):
	//     # bb
	//     ...
	//
	// we can generate the correct
	//
	// dest[i] = src[i]
	// # branch -> bb
	// while (src[i] != 0):
	//     # bb
	//     ...
	//
	ShPtr<EmptyStmt> loopPred(cast<EmptyStmt>(stmt->getUniquePredecessor()));
	if (loopPred) {
		Statement::removeStatement(loopPred);
	}

	// We place all the gathered statements that appeared before the loop
	// end statement before the loop. This has to be done because in a "while
	// true" loop, the loop's body is always accessed at least once.
	if (splittedLoop->beforeLoopEndStmts) {
		// First, however, we need to remove any metadata attached to the first
		// statement; otherwise, these metadata may contain misleading
		// information.
		splittedLoop->beforeLoopEndStmts->setMetadata("");

		// Since we use the before-the-loop's-end statements also in the loop,
		// we have to clone them.
		stmt->prependStatement(Statement::cloneStatements(
			splittedLoop->beforeLoopEndStmts));
	}

	// If there is an assignment in the loop's end, we also prepend it.
	ShPtr<AssignStmt> assignStmtInLoopEnd(cast<AssignStmt>(
		skipEmptyStmts(splittedLoop->loopEnd->getFirstIfBody())));
	if (assignStmtInLoopEnd) {
		stmt->prependStatement(ucast<Statement>(assignStmtInLoopEnd->clone()));
	}

	// We insert the stored empty statement with a debug comment before the
	// loop.
	if (loopPred) {
		stmt->prependStatement(loopPred);
	}

	// We remove the last empty statement in the original loop and store it for
	// later use; otherwise, the generated code might be misleading. A more
	// specific description of the problem: Usually, the last empty statement
	// in a "while True" loop contains metadata of the form "continue -> bb".
	// Since in the next step, we swap the statements before the original
	// loop's exit condition with the statements after the exit condition,
	// keeping this piece of information would result into improper code.
	ShPtr<Statement> lastLoopStmt = splittedLoop->afterLoopEndStmts;
	if (lastLoopStmt) {
		// When lastLoopStmt has no predecessors and successors, we have to
		// null splittedLoop->afterLoopEndStmts manually (recall that in this
		// case, Statement::removeStatement() cannot help us since it does
		// nothing). If we didn't do this, we might get into troubles.
		if (!lastLoopStmt->hasPredecessors() && !lastLoopStmt->hasSuccessor()) {
			splittedLoop->afterLoopEndStmts = ShPtr<Statement>();
		} else {
			// Go to the last statement in splittedLoop->afterLoopEndStmts, and
			// if the last statement is an empty statement, remove it.
			// Otherwise, there is nothing to store (the failed cast will set
			// lastLoopStmt to the null pointer, which is what we want).
			lastLoopStmt = cast<EmptyStmt>(
				Statement::getLastStatement(lastLoopStmt->getSuccessor()));
			if (lastLoopStmt) {
				Statement::removeStatement(lastLoopStmt);
			}
		}
	}

	// We store the metadata from the first statement in the loop. Usually,
	// these metadata contain the name of the original basic block, which we
	// should preserve.
	std::string firstStmtMetadata(stmt->getBody()->getMetadata());

	// We swap the statements before the original loop's exit condition
	// with the statements after the exit condition.
	ShPtr<Statement> newLoopBody(Statement::mergeStatements(
		splittedLoop->afterLoopEndStmts, splittedLoop->beforeLoopEndStmts));
	if (!newLoopBody) {
		// Make sure that there are some statements so the body is non-null.
		newLoopBody = EmptyStmt::create();
		// TODO Is this situation legal? It doesn't make much sense to have a
		//      WhileLoopStmt with a condition but without a body.
	}
	stmt->setBody(newLoopBody);

	// If there is an assignment in the loop's end, we also append it to
	// the end of loop's body.
	if (assignStmtInLoopEnd) {
		Statement::mergeStatements(stmt->getBody(),
			ucast<Statement>(assignStmtInLoopEnd->clone()));
	}

	// We put the stored metadata from the first statement of the original loop
	// to the first statement of the new loop.
	if (stmt->getBody()->getMetadata() != "") {
		// An empty statement need to be used.
		ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
		emptyStmt->setMetadata(firstStmtMetadata);
		stmt->getBody()->prependStatement(emptyStmt);
	} else {
		stmt->getBody()->setMetadata(firstStmtMetadata);
	}

	// We put lastLoopStmt at the end of the new loop.
	if (lastLoopStmt) {
		Statement::mergeStatements(stmt->getBody(), lastLoopStmt);
	}

	// If the exit statement of the original loop was a return statement, we
	// have to add it after the loop.
	if (ShPtr<ReturnStmt> retStmt = cast<ReturnStmt>(Statement::getLastStatement(
			splittedLoop->loopEnd->getFirstIfBody()))) {
		stmt->appendStatement(retStmt);
	}
}

} // namespace llvmir2hll
} // namespace retdec
