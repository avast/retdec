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
* TODO: prebrat s Petrom:
* - vymazanie labelu, ak nan uz neskace ziadne goto. vyzera to tak, ze
*   Statement::preds sa nedostatocne cisti. target ma v preds goto, ktore uz
*   nie su v AST.
*   politika remove/replace statment? vymazu sa tie statementy, alebo co sa s
*   nimi stane? ako dokonale sa cistia/maju cistit preds/succ?
* - opakovane spustenie tejto (inych?) analyz kym nie je dosiahnuty fixpoint? -> e.g. copy propagation
* - pustenie tejto (inych) analyz niekolko nasobne? na roznych miestach? ku
*   koncu?
* - Auto cistenie targetu, preds, succ, etc v ~GotoStmt() a inych destruktoroch?
* - goto target set, but succ nullptr.
*/
void GotoStmtOptimizer::visit(ShPtr<GotoStmt> stmt) {


std::cout << "====> this goto = " << getPtrStr(stmt.get()) << std::endl;

	auto target = stmt->getTarget();
	if (isa<GotoStmt>(target)
			|| isa<ReturnStmt>(target)
			|| isa<BreakStmt>(target)
			|| isa<ContinueStmt>(target)) {
		std::cout << "goto -> " << target->getLabel() << std::endl;

//std::cout << "\t" << "succ   = " << getPtrStr(stmt->getSuccessor().get()) << std::endl; // = nullptr
//std::cout << "\t" << "target = " << getPtrStr(stmt->getTarget().get()) << std::endl;    // = target ptr
//return;

		auto c = ucast<Statement>(target->clone());
		c->setMetadata("");

		stmt->prependStatement(c);
		Statement::removeStatement(stmt);

//		Statement::replaceStatement(stmt, c);

		if (!target->isGotoTarget()) {
			target->removeLabel();
			std::cout << "\tremoving label: " << target->getLabel() << std::endl;
		}

		for (auto it = target->predecessor_begin(), e = target->predecessor_end(); it != e; ++it) {
			auto pred = *it;

			if (auto gotoStmt = cast<GotoStmt>(pred)) {
				if (gotoStmt->getTarget() == target) {
					std::cout << std::endl;
					std::cout << "\t" << "this goto = " << getPtrStr(stmt.get())
							<< ", " << stmt->getNumberOfPredecessors() << std::endl;
					std::cout << "\t" << "pred goto = " << getPtrStr(gotoStmt.get())
								<< ", " << gotoStmt->getNumberOfPredecessors() << std::endl;
				}
			}
		}

		// TODO: remove/delete stmt?
		// Statement::removeStatement() does not seems to be doing that.
	}
}

} // namespace llvmir2hll
} // namespace retdec
