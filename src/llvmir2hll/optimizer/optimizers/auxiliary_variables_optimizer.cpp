/**
* @file src/llvmir2hll/optimizer/optimizers/auxiliary_variables_optimizer.cpp
* @brief Implementation of AuxiliaryVariablesOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/auxiliary_variables_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/auxiliary_variables_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va The used analysis of values.
* @param[in] cio Obtainer of information about function calls.
*
* @par Preconditions
*  - @a module, @a va, and @a cio are non-null
*/
AuxiliaryVariablesOptimizer::AuxiliaryVariablesOptimizer(ShPtr<Module> module,
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
			FuncOptimizer(module), cio(cio), va(va), auxVars() {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
		PRECONDITION_NON_NULL(cio);
	}

/**
* @brief Destructs the optimizer.
*/
AuxiliaryVariablesOptimizer::~AuxiliaryVariablesOptimizer() {}

void AuxiliaryVariablesOptimizer::doOptimization() {
	// Initialization.
	if (!va->isInValidState()) {
		va->clearCache();
	}
	cio->init(CGBuilder::getCG(module), va);

	// Perform the optimization on all functions.
	FuncOptimizer::doOptimization();

	// Currently, we do not update the used analysis of values (va) during this
	// optimization, so here, at the end of the optimization, we have to put it
	// into an invalid state.
	// TODO Regularly update the cache of va so we do not have to invalidate it.
	va->invalidateState();
}

void AuxiliaryVariablesOptimizer::runOnFunction(ShPtr<Function> func) {
	// Obtain all auxiliary variables in the function.
	auxVars = AuxiliaryVariablesCFGTraversal::getAuxiliaryVariables(
		module, cio, va, cio->getCFGForFunc(func));

	// Replace them with original variables. The following loop has to be done
	// first because the visitation functions modify auxVars.
	for (const auto &var : auxVars) {
		func->removeLocalVar(var);
	}
	visitStmt(func->getBody());
}

void AuxiliaryVariablesOptimizer::visit(ShPtr<AssignStmt> stmt) {
	// To optimize the statement, it should be of the form
	//
	//    a = b
	//
	// where a is the auxiliary variable and b is the original variable.
	if (ShPtr<Variable> stmtLhsVar = cast<Variable>(stmt->getLhs())) {
		if (ShPtr<Variable> stmtRhsVar = cast<Variable>(stmt->getRhs())) {
			if (hasItem(auxVars, stmtLhsVar)) {
				Expression::replaceExpression(stmtLhsVar, stmtRhsVar);
				auxVars.erase(stmtLhsVar);
				// Before removing the statement, we should try to optimized
				// nested and successive statements because after calling
				// Statement::removeStatement(), stmt might have no successor
				// set.
				FuncOptimizer::visit(stmt);
				Statement::removeStatement(stmt);
				return;
			}
		}
	}

	FuncOptimizer::visit(stmt);
}

void AuxiliaryVariablesOptimizer::visit(ShPtr<VarDefStmt> stmt) {
	// To optimize the statement, it should be of the form
	//
	//    a (= b)
	//
	// where a is the auxiliary variable and b is the original variable. If
	// there is no initializer, then it is just a VarDefStmt with no
	// initializer. Such a statement may be removed since we are removing all
	// references to a.
	if (hasItem(auxVars, stmt->getVar())) {
		if (ShPtr<Variable> stmtRhsVar = cast<Variable>(stmt->getInitializer())) {
			Expression::replaceExpression(stmt->getVar(), stmtRhsVar);
			auxVars.erase(stmt->getVar());
		}
		// Before removing the statement, we should try to optimized nested and
		// successive statements because after calling
		// Statement::removeStatement(), stmt might have no successor set.
		FuncOptimizer::visit(stmt);
		Statement::removeStatement(stmt);
		return;
	}

	FuncOptimizer::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
