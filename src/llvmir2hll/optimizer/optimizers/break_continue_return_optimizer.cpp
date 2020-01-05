/**
* @file src/llvmir2hll/optimizer/optimizers/break_continue_return_optimizer.cpp
* @brief Implementation of BreakContinueReturnOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/break_continue_return_optimizer.h"
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
BreakContinueReturnOptimizer::BreakContinueReturnOptimizer(Module* module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Removes the successor of the given statement (when appropriate).
*
* @param[in] stmt Break, continue, or return statement.
*
* @par Preconditions
*  - @a stmt is a break, continue, or return statement
*/
void BreakContinueReturnOptimizer::removeSuccessorWhenAppropriate(
		Statement* stmt) {
	PRECONDITION(isa<BreakStmt>(stmt) || isa<ContinueStmt>(stmt) ||
		isa<ReturnStmt>(stmt), "statement `" << stmt <<
		"` is not a break, continue, or return statement");

	// We have to preserve goto targets.
	if (auto succ = stmt->getSuccessor()) {
		if (!succ->isGotoTarget()) {
			stmt->setSuccessor(nullptr);
		}
	}
}

void BreakContinueReturnOptimizer::visit(BreakStmt* stmt) {
	removeSuccessorWhenAppropriate(stmt);
}

void BreakContinueReturnOptimizer::visit(ContinueStmt* stmt) {
	removeSuccessorWhenAppropriate(stmt);
}

void BreakContinueReturnOptimizer::visit(ReturnStmt* stmt) {
	removeSuccessorWhenAppropriate(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
