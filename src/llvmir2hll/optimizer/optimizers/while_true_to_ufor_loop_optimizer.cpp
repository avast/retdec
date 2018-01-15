/**
* @file src/llvmir2hll/optimizer/optimizers/while_true_to_ufor_loop_optimizer.cpp
* @brief Implementation of WhileTrueToUForLoopOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_ufor_loop_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va Analysis of values.
*
* @par Preconditions
*  - @a module and @a va are non-null
*/
WhileTrueToUForLoopOptimizer::WhileTrueToUForLoopOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va):
	FuncOptimizer(module), va(va), canBeOptimized(false) {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
	}

/**
* @brief Destructs the optimizer.
*/
WhileTrueToUForLoopOptimizer::~WhileTrueToUForLoopOptimizer() {}

void WhileTrueToUForLoopOptimizer::doOptimization() {
	if (!va->isInValidState()) {
		va->clearCache();
	}
	FuncOptimizer::doOptimization();

	// Currently, we do not update the used analysis of values (va) during this
	// optimization, so here, at the end of the optimization, we have to put it
	// into an invalid state.
	va->invalidateState();
}

/**
* @brief Tries to replace the given while loop with a universal for loop.
*/
void WhileTrueToUForLoopOptimizer::tryReplacementWithUForLoop(
		ShPtr<WhileLoopStmt> whileLoop) {
	initializeReplacement(whileLoop);
	bool infoGathered = gatherInfoAboutOptimizedWhileLoop();
	if (!infoGathered) {
		return;
	}

	// Store the last statement of the original loop for later use. Usually,
	// the last empty statement in a "while true" loop contains metadata of the
	// form "continue -> bb". To preserve this piece of information, we store
	// it and use it after the transformation if finished.
	auto lastLoopStmt = getLastEmptyStatement(splittedLoop->afterLoopEndStmts);

	// Perform the conversion and replacement.
	auto forLoop = tryConversionToUForLoop();
	if (!forLoop) {
		return;
	}
	performReplacement(forLoop);

	// Put lastLoopStmt to the end of the new loop.
	if (lastLoopStmt && lastLoopStmt->hasMetadata()) {
		Statement::mergeStatements(forLoop->getBody(), lastLoopStmt);
	}

	removeUselessSucessors(forLoop);
}

/**
* @brief Initialize a new replacement.
*/
void WhileTrueToUForLoopOptimizer::initializeReplacement(ShPtr<WhileLoopStmt> stmt) {
	whileLoop = stmt;
	splittedLoop.reset();
	canBeOptimized = true;
	toRemoveStmts.clear();
}

/**
* @brief Gathers information about the loop.
*
* @return @c true if the information was gathered successfully, @c false otherwise.
*/
bool WhileTrueToUForLoopOptimizer::gatherInfoAboutOptimizedWhileLoop() {
	// We are able to optimize only "while true" loops.
	if (!isWhileTrueLoop(whileLoop)) {
		return false;
	}

	// We have to be enable to split the loop.
	splittedLoop = splitWhileTrueLoop(whileLoop);
	if (!splittedLoop) {
		return false;
	}

	return true;
}

/**
* @brief Tries to convert the "while true" loop into a universal for loop.
*/
ShPtr<UForLoopStmt> WhileTrueToUForLoopOptimizer::tryConversionToUForLoop() {
	// TODO How to implement this optimization?
	return {};
}

/**
* @brief Returns the last empty statement in the given statements.
*/
ShPtr<EmptyStmt> WhileTrueToUForLoopOptimizer::getLastEmptyStatement(
		ShPtr<Statement> stmts) const {
	return cast<EmptyStmt>(Statement::getLastStatement(stmts));
}

/**
* @brief Removes useless successors (if any) of the given universal for loop.
*/
void WhileTrueToUForLoopOptimizer::removeUselessSucessors(
		ShPtr<UForLoopStmt> forLoop) {
	// If the successors of the resulting for loop are two empty statements
	// with metadata, remove the first one because it usually contains just an
	// end label of the original while loop.
	if (auto succ = forLoop->getSuccessor()) {
		if (isa<EmptyStmt>(succ) && succ->hasMetadata()) {
			if (auto succSucc = succ->getSuccessor()) {
				if (isa<EmptyStmt>(succSucc) && succSucc->hasMetadata()) {
					Statement::removeStatement(succ);
				}
			}
		}
	}
}

/**
* @brief Performs the replacement.
*/
void WhileTrueToUForLoopOptimizer::performReplacement(ShPtr<UForLoopStmt> forLoop) {
	Statement::replaceStatement(whileLoop, forLoop);
	removeStatementsToBeRemoved();
}

/**
* @brief Removes statements that are to be removed after a successful
*        optimization.
*/
void WhileTrueToUForLoopOptimizer::removeStatementsToBeRemoved() {
	for (auto stmt : toRemoveStmts) {
		Statement::removeStatement(stmt);
	}
}

void WhileTrueToUForLoopOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	visitNestedAndSuccessorStatements(stmt);
	tryReplacementWithUForLoop(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
