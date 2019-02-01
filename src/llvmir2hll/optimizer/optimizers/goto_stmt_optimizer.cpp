/**
* @file stc/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer.cpp
* @brief Replace goto statements when possible.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <sstream>

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

std::string getPtrStr(void* ptr) {
	std::stringstream ss;
	ss << "(" << std::hex << uint64_t(ptr) << std::dec << ")";
	return ss.str();
}

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
* @brief Destructs the optimizer.
*/
GotoStmtOptimizer::~GotoStmtOptimizer() {}

/**
* TODO
*/
void GotoStmtOptimizer::visit(ShPtr<GotoStmt> stmt) {
	auto target = stmt->getTarget();
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
	}
}

} // namespace llvmir2hll
} // namespace retdec
