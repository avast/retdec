/**
* @file src/llvmir2hll/optimizer/optimizers/simple_copy_propagation_optimizer.cpp
* @brief Implementation of SimpleCopyPropagationOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/lhs_rhs_uses_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simple_copy_propagation_optimizer.h"
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
SimpleCopyPropagationOptimizer::SimpleCopyPropagationOptimizer(ShPtr<Module> module,
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		FuncOptimizer(module), va(va), cio(cio), vuv(),
		globalVars(module->getGlobalVars()), currCFG(), triedVars() {
			PRECONDITION_NON_NULL(module);
			PRECONDITION_NON_NULL(va);
			PRECONDITION_NON_NULL(cio);
	}

/**
* @brief Destructs the optimizer.
*/
SimpleCopyPropagationOptimizer::~SimpleCopyPropagationOptimizer() {}

void SimpleCopyPropagationOptimizer::doOptimization() {
	// Initialization.
	// We clear the cache of va even if it is in a valid state (this
	// surprisingly speeds up the optimization).
	va->clearCache();
	va->initAliasAnalysis(module);
	cio->init(CGBuilder::getCG(module), va);
	vuv = VarUsesVisitor::create(va, true, module);

	FuncOptimizer::doOptimization();
}

void SimpleCopyPropagationOptimizer::runOnFunction(ShPtr<Function> func) {
	currCFG = cio->getCFGForFunc(func);
	triedVars.clear();

	FuncOptimizer::runOnFunction(func);
}

void SimpleCopyPropagationOptimizer::visit(ShPtr<AssignStmt> stmt) {
	// First, visit nested statements.
	FuncOptimizer::visit(stmt);

	tryOptimization(stmt);
}

void SimpleCopyPropagationOptimizer::visit(ShPtr<VarDefStmt> stmt) {
	// First, visit nested statements.
	FuncOptimizer::visit(stmt);

	tryOptimization(stmt);
}

/**
* @brief Tries to perform the optimization on the given statement.
*
* @par Preconditions
*  - @a stmt is either a VarDefStmt or AssignStmt
*/
void SimpleCopyPropagationOptimizer::tryOptimization(ShPtr<Statement> stmt) {
	ShPtr<Variable> lhsVar(cast<Variable>(getLhs(stmt)));
	ShPtr<Expression> rhs(getRhs(stmt));
	if (!lhsVar || !rhs) {
		// There is nothing we can do in this case.
		return;
	}

	if (hasItem(triedVars, lhsVar)) {
		// We have already tried this variable.
		return;
	}
	triedVars.insert(lhsVar);

	if (!currFunc->hasLocalVar(lhsVar)) {
		// The left-hand side is not a local variable.
		return;
	}

	if (module->hasAssignedDebugName(lhsVar)) {
		// The left-hand side has assigned a name from debug information.
		return;
	}

	if (lhsVar->isExternal()) {
		// We do not want to optimize external variables (used in a volatile
		// load/store).
		return;
	}

	if (va->mayBePointed(lhsVar)) {
		// The left-hand side may be used indirectly.
		return;
	}

	if (isa<ConstString>(rhs) || isa<ConstArray>(rhs) || isa<ConstStruct>(rhs)) {
		// The expression cannot be any of the above types.
		// TODO What about dropping this restriction?
		return;
	}

	if (lhsVar == rhs) {
		// Do not optimize self assigns, i.e. statements of the form `a = a;`.
		// This is done in other optimizations.
		return;
	}

	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	if (stmtData->hasAddressOps() || stmtData->hasDerefs() ||
			stmtData->hasArrayAccesses() || stmtData->hasStructAccesses()) {
		// A forbidden construction is used.
		return;
	}

	// Try to perform the proper case of the optimization (see the class
	// description).
	if (stmtData->hasCalls()) {
		tryOptimizationCase1(stmt, lhsVar, rhs);
	} else {
		tryOptimizationCase2(stmt, lhsVar, rhs);
	}
}

/**
* @brief Tries to perform the case (1) optimization from the class description
*        on the given statement.
*
* For the preconditions, see tryOptimization(), which is the place from where
* this function should be called.
*/
void SimpleCopyPropagationOptimizer::tryOptimizationCase1(
		ShPtr<Statement> stmt, ShPtr<Variable> lhsVar, ShPtr<Expression> rhs) {
	// Currently, we can only handle the situation where the right-hand side is
	// a function call; that is, there are no other computations.
	// TODO Add some more robust analysis to handle also this case.
	ShPtr<CallExpr> rhsCall(cast<CallExpr>(rhs));
	if (!rhsCall) {
		return;
	}

	// We will need the set of variables which may be accessed when calling the
	// function from the right-hand side.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	const VarSet &varsAccessedInCall(stmtData->getDirAccessedVars());
	ShPtr<CallInfo> rhsCallInfo(cio->getCallInfo(rhsCall, currFunc));

	// Get the first statement where the variable is used by going through the
	// successors of stmt. During this traversal, check that the optimization
	// can be done.
	ShPtr<Statement> firstUseStmt(stmt->getSuccessor());
	ShPtr<ValueData> firstUseStmtData;
	while (firstUseStmt) {
		firstUseStmtData = va->getValueData(firstUseStmt);
		if (firstUseStmtData->isDirAccessed(lhsVar)) {
			// Got it.
			break;
		}

		// There cannot be a compound statement.
		// TODO Add some more robust analysis to handle also this case.
		if (firstUseStmt->isCompound()) {
			return;
		}

		// There cannot be other calls, dereferences, or other possibly
		// "dangerous" constructs.
		if (firstUseStmtData->hasCalls() || firstUseStmtData->hasAddressOps() ||
				firstUseStmtData->hasDerefs() ||
				firstUseStmtData->hasArrayAccesses() ||
				firstUseStmtData->hasStructAccesses()) {
			return;
		}

		// The statement cannot contain a variable which is accessed in the
		// original call from the right-hand side (both directly and
		// indirectly).
		for (auto i = firstUseStmtData->dir_all_begin(),
				e = firstUseStmtData->dir_all_end(); i != e; ++i) {
			if (hasItem(varsAccessedInCall, *i) ||
					rhsCallInfo->mayBeRead(*i) ||
					rhsCallInfo->mayBeModified(*i)) {
				return;
			}
		}

		// Keep traversing.
		firstUseStmt = firstUseStmt->getSuccessor();
	}

	// The statement where lhsVar is used after stmt has to exist.
	if (!firstUseStmt) {
		return;
	}

	// This variable has to be used precisely once in there.
	if (firstUseStmtData->getDirNumOfUses(lhsVar) != 1) {
		return;
	}

	// There should not be any dereferences or other constructs that may cause
	// problems.
	if (firstUseStmtData->hasAddressOps() || firstUseStmtData->hasDerefs() ||
			firstUseStmtData->hasArrayAccesses() ||
			firstUseStmtData->hasStructAccesses()) {
		return;
	}

	// If there is a call, make sure that the statement is either of the form
	//
	//     return call(a, b, c, ...)
	//
	// or
	//
	//     x = call(a, b, c, ...)
	//
	// or
	//
	//     call(a, b, c, ...)
	//
	// where a, b, c, ... are expressions that use only local variables and do
	// not contain any function calls.
	if (firstUseStmtData->hasCalls()) {
		if (firstUseStmtData->getNumOfCalls() != 1) {
			return;
		}

		if (ShPtr<ReturnStmt> returnStmt = cast<ReturnStmt>(firstUseStmt)) {
			if (!isa<CallExpr>(returnStmt->getRetVal())) {
				return;
			}
		} else if (ShPtr<AssignStmt> assignStmt = cast<AssignStmt>(firstUseStmt)) {
			if (!isa<CallExpr>(assignStmt->getRhs())) {
				return;
			}
		} else if (!isa<CallStmt>(firstUseStmt)) {
			return;
		}

		for (auto i = firstUseStmtData->dir_read_begin(),
				e = firstUseStmtData->dir_read_end(); i != e; ++i) {
			if (hasItem(globalVars, *i)) {
				return;
			}
		}
	}

	// The next statement cannot be a while or for loop. Otherwise, we would
	// optimize
	//
	//     a = rand()
	//     while (a) {
	//         // ...
	//     }
	//
	// to
	//
	//     while (rand()) {
	//         // ...
	//     }
	//
	// which may not be correct.
	if (isLoop(firstUseStmt)) {
		return;
	}

	// Check that the two uses in stmt and firstUseStmt are the only uses of
	// lhsVar, with the exception of an optional variable-defining statement.
	ShPtr<VarDefStmt> lhsDefStmt;
	ShPtr<VarUses> allLhsUses(vuv->getUses(lhsVar, currFunc));
	for (const auto &dirUse : allLhsUses->dirUses) {
		if (dirUse == stmt || dirUse == firstUseStmt) {
			continue;
		}

		lhsDefStmt = cast<VarDefStmt>(dirUse);
		if (!lhsDefStmt || lhsDefStmt->getVar() != lhsVar ||
				lhsDefStmt->getInitializer()) {
			return;
		}
	}

	// Do the optimization.
	replaceVarWithExprInStmt(lhsVar, rhs, firstUseStmt);
	va->removeFromCache(firstUseStmt);
	Statement::removeStatementButKeepDebugComment(stmt);
	currCFG->removeStmt(stmt);
	if (lhsDefStmt) {
		removeVarDefOrAssignStatement(lhsDefStmt, currFunc);
		currCFG->removeStmt(lhsDefStmt);
	}
}

/**
* @brief Tries to perform the case (2) optimization from the class description
*        on the given statement.
*
* For the preconditions, see tryOptimization(), which is the place from where
* this function should be called.
*/
void SimpleCopyPropagationOptimizer::tryOptimizationCase2(
		ShPtr<Statement> stmt, ShPtr<Variable> lhsVar, ShPtr<Expression> rhs) {
	// TODO Currently, we optimize (2) only if `expr` is a variable. Otherwise,
	//      in some cases, the result of the optimization is less readable than
	//      the original code.
	// TODO When optimizing also non-variable expressions, we have to use
	//      clone() when replacing the expression. Otherwise, there may be
	//      several expressions with the same address.
	if (!isa<Variable>(rhs)) {
		return;
	}

	// First, check whether the optimization can be done.
	StmtSet lhsUses(LhsRhsUsesCFGTraversal::getUses(stmt, currCFG, va, cio));
	if (lhsUses.empty()) {
		return;
	}

	// Check the correspondence between allLhsUses and lhsUses. In a greater
	// detail, allLhsUses has to contain all the statements in lhsUses + stmt
	// and possibly a variable-defining statement defining lhsVar without an
	// initializer.
	// TODO Can this restriction (empty initializer) be relaxed a bit?
	ShPtr<VarDefStmt> lhsDefStmt;
	ShPtr<VarUses> allLhsUses(vuv->getUses(lhsVar, currFunc));
	for (const auto &dirUse : allLhsUses->dirUses) {
		if (hasItem(lhsUses, dirUse) || stmt == dirUse) {
			continue;
		}

		lhsDefStmt = cast<VarDefStmt>(dirUse);
		if (!lhsDefStmt || lhsDefStmt->getVar() != lhsVar ||
				lhsDefStmt->getInitializer()) {
			return;
		}
	}

	// Do the optimization.
	for (const auto &lhsUse : lhsUses) {
		replaceVarWithExprInStmt(lhsVar, getRhs(stmt), lhsUse);
		va->removeFromCache(lhsUse);
	}
	removeVarDefOrAssignStatement(stmt);
	currCFG->removeStmt(stmt);
	if (lhsDefStmt) {
		removeVarDefOrAssignStatement(lhsDefStmt, currFunc);
		currCFG->removeStmt(lhsDefStmt);
	}
}

} // namespace llvmir2hll
} // namespace retdec
