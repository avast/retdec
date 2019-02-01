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

#include "retdec/llvmir2hll/hll/bir_writer.h"

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

//BIRWriter bw;

	//
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

	return;

	//
	//
	if (target->getNumberOfPredecessors() == 1) {
		auto pred = *target->predecessor_begin();
		if (pred != stmt) {
			assert(false && "Should never happen.");
			return;
		}

//bw.emit(module);

//		std::set<ShPtr<Statement>> seen;
//		auto succ = target;
//		seen.insert(succ);
//		while (succ)
//		{
//			if (succ == stmt) {
//				std::cout << "=======> SHIT" << std::endl;
//				return;
//			}
//			succ = target->getSuccessor();
//			if (seen.count(succ)) {
//				break;
//			} else {
//				seen.insert(succ);
//			}
//		}

//		stmt->prependStatement(target);
//		Statement::removeStatement(stmt);

		Statement::replaceStatement(stmt, target);
//		Statement::removeStatement(stmt);

		if (!target->isGotoTarget()) {
			target->removeLabel();
		}

//bw.emit(module);

		return;
	}
}

} // namespace llvmir2hll
} // namespace retdec
