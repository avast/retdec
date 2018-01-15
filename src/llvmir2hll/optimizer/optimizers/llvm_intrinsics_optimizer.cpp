/**
* @file src/llvmir2hll/optimizer/optimizers/llvm_intrinsics_optimizer.cpp
* @brief Implementation of LLVMIntrinsicsOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/llvm_intrinsics_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"

using retdec::utils::hasItem;
using retdec::utils::startsWith;

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
LLVMIntrinsicsOptimizer::LLVMIntrinsicsOptimizer(ShPtr<Module> module):
	FuncOptimizer(module), doNotRemoveFuncs(), removedCalls() {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
LLVMIntrinsicsOptimizer::~LLVMIntrinsicsOptimizer() {}

void LLVMIntrinsicsOptimizer::doOptimization() {
	FuncOptimizer::doOptimization();

	// Remove the declarations of unused functions.
	for (const auto &func : removedCalls) {
		if (!hasItem(doNotRemoveFuncs, func)) {
			module->removeFunc(func);
		}
	}
}

/**
* @brief Returns the function called in @a expr.
*
* If the called expression is something more complex, like an indirect call, it
* returns the null pointer.
*/
ShPtr<Function> LLVMIntrinsicsOptimizer::getCalledFunc(ShPtr<CallExpr> expr) const {
	ShPtr<Variable> callAsVar(cast<Variable>(expr->getCalledExpr()));
	if (!callAsVar) {
		// The called expression is something complex.
		return ShPtr<Function>();
	}

	ShPtr<Function> calledFunc(module->getFuncByName(callAsVar->getName()));
	if (!calledFunc) {
		// Indirect call.
		return ShPtr<Function>();
	}

	return calledFunc;
}

void LLVMIntrinsicsOptimizer::visit(ShPtr<CallExpr> expr) {
	// When we got here, we know that such a call should not be removed. Hence,
	// we just check that the call is a function call (not some indirect call)
	// and insert the call into doNotRemoveFuncs.
	ShPtr<Function> calledFunc(getCalledFunc(expr));
	if (calledFunc) {
		doNotRemoveFuncs.insert(calledFunc);
	}

	FuncOptimizer::visit(expr);
}

void LLVMIntrinsicsOptimizer::visit(ShPtr<CallStmt> stmt) {
	ShPtr<Function> calledFunc(getCalledFunc(stmt->getCall()));
	if (!calledFunc || calledFunc->isDefinition() ||
			!startsWith(calledFunc->getInitialName(), "llvm.ctpop.")) {
		FuncOptimizer::visit(stmt);
		return;
	}

	// It is a call to llvm.ctpop.*. Remove it.
	ShPtr<Statement> stmtSucc(stmt->getSuccessor());
	removedCalls.insert(calledFunc);
	Statement::removeStatementButKeepDebugComment(stmt);
	if (stmtSucc) {
		FuncOptimizer::visitStmt(stmtSucc);
	}
}

} // namespace llvmir2hll
} // namespace retdec
