/**
* @file src/llvmir2hll/optimizer/optimizers/unreachable_code_optimizer.cpp
* @brief Implementation of UnreachableCodeOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/unreachable_code_optimizer.h"
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/unreachable_code_in_cfg_remover.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va @a Analysis of values.
*
* @par Preconditions
*  - both @a module and @a va are non-null
*/
UnreachableCodeOptimizer::UnreachableCodeOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va):
	FuncOptimizer(module), va(va) {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
	}

/**
* @brief Destructs the optimizer.
*/
UnreachableCodeOptimizer::~UnreachableCodeOptimizer() {}

void UnreachableCodeOptimizer::doOptimization() {
	if (!va->isInValidState()) {
		va->clearCache();
	}
	FuncOptimizer::doOptimization();

	// Clean-up the code.
	UnreachableCodeInCFGRemover::removeCode(module);
}

/**
* @brief Returns @c true if @a stmt is a call of a declared function that never
*        returns, @c false otherwise.
*/
bool UnreachableCodeOptimizer::isCallOfDeclaredFuncThatNeverReturns(
		ShPtr<CallStmt> stmt) const {
	ShPtr<Variable> callAsVar(cast<Variable>(stmt->getCall()->getCalledExpr()));
	if (!callAsVar) {
		// The called expression is something complex.
		return false;
	}

	std::string calledFuncName(callAsVar->getName());
	ShPtr<Function> calledFunc(module->getFuncByName(calledFuncName));
	if (!calledFunc) {
		// Indirect call.
		return false;
	}

	if (!calledFunc->isDeclaration()) {
		// We are calling a function that is defined, so we do not know whether
		// it never returns or not.
		// TODO This can be improved by performing an additional analysis over
		//      the defined functions. Maybe in CallInfoObtainer? However,
		//      after that, the name of this function should be changed.
		return false;
	}

	Maybe<bool> funcNeverReturns(module->getSemantics()->funcNeverReturns(
		calledFuncName));
	if (funcNeverReturns) {
		return funcNeverReturns.get();
	}
	return false;
}

/**
* @brief Returns @c true if the successor of the given statement is unreachable
*        by normal program flow (no gotos), @c false otherwise.
*/
bool UnreachableCodeOptimizer::isSuccessorUnreachable(
		ShPtr<CallStmt> stmt) const {
	if (isa<UnreachableStmt>(stmt->getSuccessor())) {
		return true;
	}
	return isCallOfDeclaredFuncThatNeverReturns(stmt);
}

/**
* @brief Performs the unreachable code optimization over the given statement.
*
* See the class description for more details.
*/
void UnreachableCodeOptimizer::performOptimization(ShPtr<CallStmt> stmt) {
	//
	// Optimize code after the statement.
	//
	// Since we use UnreachableCodeInCFGRemover to clean-up at the end of this
	// optimization, we may simply make the successor of the statement
	// unreachable.
	if (!isa<UnreachableStmt>(stmt->getSuccessor())) {
		stmt->appendStatement(UnreachableStmt::create());
	}

	//
	// Optimize code before the statement.
	//
	// Do this only if the function called in stmt is a declared function that
	// never returns. Otherwise, if it is a defined function, the variables set
	// before this statement may be needed so they can't be removed.
	//
	if (!isCallOfDeclaredFuncThatNeverReturns(stmt)) {
		// TODO Use CallObtainer to find out whether the statements before the
		//      call in this case are needed; if not, remove them.
		return;
	}

	// We keep removing the code until we find a place where to stop.
	ShPtr<Statement> stmtPred(stmt->getUniquePredecessor());
	while (stmtPred) {
		// Compound statement.
		// TODO Can we improve this by also traversing the bodies of compound
		//      statements?
		if (stmtPred->isCompound()) {
			break;
		}

		// Function call.
		ShPtr<ValueData> stmtPredData(va->getValueData(stmtPred));
		if (stmtPredData->hasCalls()) {
			break;
		}

		// Do not remove goto statements or targets.
		if (isa<GotoStmt>(stmtPred) || stmtPred->isGotoTarget()) {
			break;
		}

		// Remove the predecessor and go to the next one.
		ShPtr<Statement> newStmtPred(stmtPred->getUniquePredecessor());
		Statement::removeStatementButKeepDebugComment(stmtPred);
		stmtPred = newStmtPred;
	}
}

void UnreachableCodeOptimizer::visit(ShPtr<CallStmt> stmt) {
	if (isSuccessorUnreachable(stmt)) {
		performOptimization(stmt);
	}
	FuncOptimizer::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
