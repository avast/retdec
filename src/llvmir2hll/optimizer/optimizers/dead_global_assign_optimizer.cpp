/**
* @file src/llvmir2hll/optimizer/optimizers/dead_global_assign_optimizer.cpp
* @brief Implementation of DeadGlobalAssignOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/modified_before_read_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_global_assign_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
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
* @param[in] cio Obtainer of information about function calls.
*
* @par Preconditions
*  - @a module, @a va, and @a cio are non-null
*/
DeadGlobalAssignOptimizer::DeadGlobalAssignOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
	FuncOptimizer(module), va(va), cio(cio),
	cfgBuilder(NonRecursiveCFGBuilder::create()),
	globalVars(module->getGlobalVars()), codeChanged(false) {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
		PRECONDITION_NON_NULL(cio);
	}

/**
* @brief Destructs the optimizer.
*/
DeadGlobalAssignOptimizer::~DeadGlobalAssignOptimizer() {}

void DeadGlobalAssignOptimizer::doOptimization() {
	// Initialization.
	if (!va->isInValidState()) {
		va->clearCache();
	}
	cio->init(CGBuilder::getCG(module), va);

	// Perform the optimization on all functions.
	FuncOptimizer::doOptimization();
}

void DeadGlobalAssignOptimizer::runOnFunction(ShPtr<Function> func) {
	// Get a CFG for the current function (it is needed in canBeOptimized).
	currCFG = cio->getCFGForFunc(func);
	if (!currCFG) {
		currCFG = cfgBuilder->getCFG(func);
	}

	// Keep optimizing until the code is left unchanged.
	do {
		codeChanged = false;
		FuncOptimizer::runOnFunction(func);
	} while (codeChanged);
}

/**
* @brief Returns @c true if the given assign statement can be optimized, @c
*        false otherwise.
*/
bool DeadGlobalAssignOptimizer::canBeOptimized(ShPtr<AssignStmt> stmt) {
	// We only optimize assignments into global variables.
	ShPtr<Variable> lhsVar(cast<Variable>(stmt->getLhs()));
	if (!lhsVar || !hasItem(globalVars, lhsVar)) {
		return false;
	}

	// We do not optimize external global variables because we may not have all
	// the available information for them (for example, in selective
	// decompilation, an external variable may be changed outside of the
	// decompiled code).
	if (lhsVar->isExternal()) {
		return false;
	}

	// The assignment cannot be the last statement in the function.
	ShPtr<Statement> stmtSucc(skipEmptyStmts(stmt->getSuccessor()));
	if (!stmtSucc) {
		return false;
	}

	// The successor has to reachable in the CFG; otherwise, we cannot use
	// ModifiedBeforeReadCFGTraversal below.
	if (!currCFG->hasNodeForStmt(stmtSucc)) {
		return false;
	}

	// Check that the global variable is modified before all reads in the
	// subsequent statements.
	if (!ModifiedBeforeReadCFGTraversal::isModifiedBeforeEveryRead(lhsVar,
			stmtSucc, currCFG, va, cio)) {
		return false;
	}

	return true;
}

void DeadGlobalAssignOptimizer::visit(ShPtr<AssignStmt> stmt) {
	FuncOptimizer::visit(stmt);

	if (canBeOptimized(stmt)) {
		auto newStmts = removeVarDefOrAssignStatement(stmt);
		currCFG->replaceStmt(stmt, newStmts);
		codeChanged = true;
	}
}

} // namespace llvmir2hll
} // namespace retdec
