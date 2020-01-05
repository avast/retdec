/**
* @file src/llvmir2hll/graphs/cg/cg_builder.cpp
* @brief Implementation of CGBuilder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new builder.
*/
CGBuilder::CGBuilder(Module* module):
	OrderedAllVisitor(), cg(new CG(module)) {}

/**
* @brief Returns a CG of the given @a module.
*
* @par Preconditions
*  - @a module is non-null
*/
CG* CGBuilder::getCG(Module* module) {
	PRECONDITION_NON_NULL(module);

	// Build the CG.
	CGBuilder* builder(new CGBuilder(module));
	builder->computeCG();
	return builder->cg;
}

/**
* @brief Computes the CG.
*/
void CGBuilder::computeCG() {
	// For each function in the module...
	for (auto i = cg->module->func_begin(), e = cg->module->func_end();
			i != e; ++i) {
		cg->callerCalleeMap[*i] = computeCGPartForFunction(*i);
	}
}

/**
* @brief Computes a part of the call graph from the given function and returns
*        it.
*
* @a func may be a definition or a declaration.
*/
CG::CalledFuncs* CGBuilder::computeCGPartForFunction(Function* func) {
	calledFuncs = new CG::CalledFuncs(func);

	if (func->isDeclaration()) {
		// It is a declaration, so we're done.
		return calledFuncs;
	}

	// It is a definition, so obtain all the called functions.
	restart(true, true);
	visitStmt(func->getBody());
	return calledFuncs;
}

void CGBuilder::visit(CallExpr* expr) {
	OrderedAllVisitor::visit(expr);

	// Skip any casts, which are irrelevant when looking for called functions.
	Expression* callExpr(skipCasts(expr->getCalledExpr()));

	if (isCallByPointer(callExpr, cg->module)) {
		// There is a call by a pointer.
		calledFuncs->callsByPointer = true;
		return;
	}

	// Since it is not a call by a pointer, it has to be a direct call.
	Variable* calledFuncVar(cast<Variable>(callExpr));
	Function* calledFunc(cg->module->getFuncByName(
		calledFuncVar->getName()));
	ASSERT_MSG(calledFunc, "isCallByPointer() probably didn't work correctly");
	calledFuncs->callees.insert(calledFunc);
	if (calledFunc->isDeclaration()) {
		calledFuncs->callsOnlyDefinedFuncs = false;
	}
}

} // namespace llvmir2hll
} // namespace retdec
