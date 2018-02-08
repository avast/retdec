/**
* @file src/llvmir2hll/optimizer/optimizers/dead_local_assign_optimizer.cpp
* @brief Implementation of DeadLocalAssignOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_local_assign_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va Analysis of values.
*
* @par Preconditions
*  - @a module and @a va are non-null
*/
DeadLocalAssignOptimizer::DeadLocalAssignOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va):
	FuncOptimizer(module), va(va), vuv() {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
	}

/**
* @brief Destructs the optimizer.
*/
DeadLocalAssignOptimizer::~DeadLocalAssignOptimizer() {}

void DeadLocalAssignOptimizer::doOptimization() {
	// Initialization.
	if (!va->isInValidState()) {
		va->clearCache();
	}
	vuv = VarUsesVisitor::create(va, true, module);

	// Perform the optimization on all functions.
	FuncOptimizer::doOptimization();
}

void DeadLocalAssignOptimizer::runOnFunction(ShPtr<Function> func) {
	// Keep optimizing until the code is left unchanged.
	bool codeChanged = false;
	do {
		codeChanged = tryToOptimize(func);
	} while (codeChanged);
}

/**
* @brief Returns @c true if the given variable with the given uses can be
*        optimized, @c false otherwise.
*/
bool DeadLocalAssignOptimizer::canBeOptimized(ShPtr<Variable> var,
		ShPtr<VarUses> varUses) {
	// For every direct use of the variable...
	for (const auto &use : varUses->dirUses) {
		// The use has to be a variable-defining/assign statement.
		if (!isVarDefOrAssignStmt(use)) {
			return false;
		}

		// The use has to have the variable on its left-hand side.
		if (getLhs(use) != var) {
			return false;
		}

		// The variable is not read in the use.
		ShPtr<ValueData> useData(va->getValueData(use));
		if (hasItem(useData->getDirReadVars(), var)) {
			return false;
		}

		// We do not want to optimize external variables (used in a volatile
		// load/store).
		if (var->isExternal()) {
			return false;
		}

		// The use cannot contain any function calls.
		if (useData->hasCalls()) {
			return false;
		}
	}

	return true;
}

/**
* @brief Tries to optimize the given function.
*
* @return @c true if the code of the function was changed, @c false otherwise.
*/
bool DeadLocalAssignOptimizer::tryToOptimize(ShPtr<Function> func) {
	bool codeChanged = false;

	// For every local variable in the function (excluding parameters)...
	for (const auto &var : func->getLocalVars()) {
		// Check that all uses satisfy certain conditions.
		ShPtr<VarUses> varUses(vuv->getUses(var, func));
		if (!canBeOptimized(var, varUses)) {
			continue;
		}

		// All uses satisfy the required conditions, so we can remove them.
		// Since the vuv->stmtHasBeenRemoved() call below modifies
		// varUses->dirUses, we have to create a copy of this set and iterate
		// over this copy.
		for (const auto &use : StmtSet(varUses->dirUses)) {
			removeVarDefOrAssignStatement(use, func);
			codeChanged = true;
			va->removeFromCache(use);
			vuv->stmtHasBeenRemoved(use, func);
		}
	}

	return codeChanged;
}

} // namespace llvmir2hll
} // namespace retdec
