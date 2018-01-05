/**
* @file src/llvmir2hll/analysis/indirect_func_ref_analysis.cpp
* @brief Implementation of IndirectFuncRefAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/indirect_func_ref_analysis.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new analysis.
*/
IndirectFuncRefAnalysis::IndirectFuncRefAnalysis(ShPtr<Module> module):
	OrderedAllVisitor(), module(module) {}

/**
* @brief Destructs the analysis.
*/
IndirectFuncRefAnalysis::~IndirectFuncRefAnalysis() {}

/**
* @brief Returns the set of functions that are referenced outside of direct
*        function calls in the given @a module.
*
* @par Preconditions
*  - @a module is non-null
*/
FuncSet IndirectFuncRefAnalysis::getIndirectlyReferencedFuncs(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	ShPtr<IndirectFuncRefAnalysis> analysis(new IndirectFuncRefAnalysis(module));
	analysis->performAnalysis();
	return analysis->indirRefdFuncs;
}

/**
* @brief Returns the set of functions that are reference outside of function
*        calls in the given @a module.
*
* @par Preconditions
*  - @a module is non-null
*/
bool IndirectFuncRefAnalysis::isIndirectlyReferenced(ShPtr<Module> module,
		ShPtr<Function> func) {
	return hasItem(getIndirectlyReferencedFuncs(module), func);
}

/**
* @brief Performs the analysis.
*/
void IndirectFuncRefAnalysis::performAnalysis() {
	restart();
	visitAllFuncs();
}

/**
* @brief Visits all the functions in the given module.
*/
void IndirectFuncRefAnalysis::visitAllFuncs() {
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		currFunc = *i;
		currFunc->accept(this);
	}
}

/**
* @brief Checks whether the given called expression should be visited.
*/
bool IndirectFuncRefAnalysis::shouldCalledExprBeVisited(ShPtr<Expression> expr) {
	// The called expression should be visited only in the case of indirect
	// function calls. Indeed, if a variable is called in a direct function
	// call, such a variable cannot represent a function that is called
	// indirectly (at least not in this particular case).
	return !isa<Variable>(expr);
}

/**
* @brief Visits all the given arguments.
*/
void IndirectFuncRefAnalysis::visitArgs(const ExprVector &args) {
	for (const auto &arg : args) {
		arg->accept(this);
	}
}

void IndirectFuncRefAnalysis::visit(ShPtr<CallExpr> expr) {
	ShPtr<Expression> calledExpr(expr->getCalledExpr());
	if (shouldCalledExprBeVisited(calledExpr)) {
		calledExpr->accept(this);
	}

	visitArgs(expr->getArgs());
}

void IndirectFuncRefAnalysis::visit(ShPtr<Variable> var) {
	// Ignore functions that are named as one of the parameters of local
	// variables.
	if (currFunc->hasLocalVar(var, true)) {
		return;
	}

	if (ShPtr<Function> func = module->getFuncByName(var->getName())) {
		indirRefdFuncs.insert(func);
	}
}

} // namespace llvmir2hll
} // namespace retdec
