/**
* @file src/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer.cpp
* @brief Replace goto statements when possible.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer.h"
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
GotoStmtOptimizer::GotoStmtOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Optimize goto statement.
*/
void GotoStmtOptimizer::visit(ShPtr<GotoStmt> stmt) {
	auto target = stmt->getTarget();

	// goto label
	// ...
	// label:
	//   goto/return/break/continue
	//
	// ==>
	//
	// cloned goto/return/break/continue
	// ...
	// label: (possibly remove if no goto label left)
	//   goto/return/break/continue
	//
	if (isa<GotoStmt>(target)
			|| isa<ReturnStmt>(target)
			|| isa<BreakStmt>(target)
			|| isa<ContinueStmt>(target)) {
		auto c = ucast<Statement>(target->clone());
		c->setMetadata("");

		stmt->prependStatement(c);
		Statement::removeStatement(stmt);

		if (!target->isGotoTarget()) {
			target->removeLabel();
		}

		return;
	}
}

} // namespace llvmir2hll
} // namespace retdec
