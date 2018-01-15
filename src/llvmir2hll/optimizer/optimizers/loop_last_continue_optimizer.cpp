/**
* @file src/llvmir2hll/optimizer/optimizers/loop_last_continue_optimizer.cpp
* @brief Implementation of LoopLastContinueOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/loop_last_continue_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

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
LoopLastContinueOptimizer::LoopLastContinueOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
LoopLastContinueOptimizer::~LoopLastContinueOptimizer() {}

void LoopLastContinueOptimizer::visit(ShPtr<ForLoopStmt> stmt) {
	tryToOptimize(stmt);

	FuncOptimizer::visit(stmt);
}

void LoopLastContinueOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	tryToOptimize(stmt);

	FuncOptimizer::visit(stmt);
}

/**
* @brief Tries to optimize the given loop.
*
* @par Preconditions
*  - @a stmt is either a WhileLoopStmt or ForLoopStmt
*/
void LoopLastContinueOptimizer::tryToOptimize(ShPtr<Statement> stmt) {
	// Get the loop's body.
	ShPtr<Statement> loopBody;
	if (ShPtr<WhileLoopStmt> whileLoop = cast<WhileLoopStmt>(stmt)) {
		loopBody = whileLoop->getBody();
	} else if (ShPtr<ForLoopStmt> forLoop = cast<ForLoopStmt>(stmt)) {
		loopBody = forLoop->getBody();
	} else {
		PRECONDITION(isa<WhileLoopStmt>(stmt) || isa<ForLoopStmt>(stmt),
			"stmt has to be either a WhileLoopStmt or ForLoopStmt");
		return;
	}

	// Go to the end of the loop.
	ShPtr<Statement> lastStmt(Statement::getLastStatement(loopBody));

	// It should be a continue statement; otherwise, there is nothing we can do.
	ShPtr<ContinueStmt> continueStmt(cast<ContinueStmt>(lastStmt));
	if (!continueStmt) {
		return;
	}

	// Ignore continues which are the only statement in the current loop.
	if (loopBody == continueStmt) {
		return;
	}

	// Optimize the statement.
	Statement::removeStatementButKeepDebugComment(continueStmt);
}

} // namespace llvmir2hll
} // namespace retdec
