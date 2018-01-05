/**
* @file src/llvmir2hll/optimizer/optimizers/pre_while_true_loop_conv_optimizer.cpp
* @brief Implementation of PreWhileTrueLoopConvOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/pre_while_true_loop_conv_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"

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
PreWhileTrueLoopConvOptimizer::PreWhileTrueLoopConvOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va):
	FuncOptimizer(module), va(va), vuv() {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
	}

/**
* @brief Destructs the optimizer.
*/
PreWhileTrueLoopConvOptimizer::~PreWhileTrueLoopConvOptimizer() {}

void PreWhileTrueLoopConvOptimizer::doOptimization() {
	if (!va->isInValidState()) {
		va->clearCache();
	}
	va->initAliasAnalysis(module);
	// It is more faster without pre-computation, so do not pass the module to
	// the following create() call.
	vuv = VarUsesVisitor::create(va, true);
	FuncOptimizer::doOptimization();

	// Currently, we do not update the used analysis of values (va) during this
	// optimization, so here, at the end of the optimization, we have to put it
	// into an invalid state.
	// TODO Regularly update the cache of va so we do not have to invalidate it.
	//      However, is (or will be) this feasible?
	va->invalidateState();
}

void PreWhileTrueLoopConvOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Ignore while loops where the condition is not the constant "true".
	if (!isWhileTrueLoop(stmt)) {
		return;
	}

	tryOptimizationCase1(stmt);
	tryOptimizationCase2(stmt);
	tryOptimizationCase3(stmt);
	tryOptimizationCase4(stmt);
	tryOptimizationCase5(stmt);
}

/**
* @brief Tries the optimization (1) from the class description over the given
*        loop.
*
* @return @c true if the optimization was done, @c false otherwise.
*
* @par Preconditions
*  - @a stmt is a `while True` loop
*/
bool PreWhileTrueLoopConvOptimizer::tryOptimizationCase1(
		ShPtr<WhileLoopStmt> stmt) {

	// Check whether the loop is of the following form:
	//
	//   while True:
	//       ...
	//       tmp = i + 1
	//       if tmp >= 1:
	//           break
	//       i = tmp
	//
	// (Of course, the constants an conditions may be different.)

	// Try to split the loop.
	ShPtr<SplittedWhileTrueLoop> splittedLoop(splitWhileTrueLoop(stmt));
	if (!splittedLoop) {
		return false;
	}

	// If the if statement has none or more than one predecessor, we cannot
	// continue.
	if (splittedLoop->loopEnd->getNumberOfPredecessors() != 1) {
		return false;
	}

	// If the code is of the following form:
	//
	//       tmp = i + 1
	//       // ... optional function calls
	//       if tmp >= 1:
	//
	// then skip the calls.
	// TODO Use CallInfoObtainer to make sure the calls do not modify the
	//      variables tmp and i.
	ShPtr<Statement> stmtBeforeIf(splittedLoop->loopEnd->getUniquePredecessor());
	while (stmtBeforeIf && isa<CallStmt>(stmtBeforeIf) &&
			stmtBeforeIf->getNumberOfPredecessors() == 1) {
		stmtBeforeIf = stmtBeforeIf->getUniquePredecessor();
	}
	ShPtr<AssignStmt> assignBeforeIf(cast<AssignStmt>(stmtBeforeIf));
	if (!assignBeforeIf) {
		return false;
	}

	// Check that the variable used in the break condition is assigned before
	// the if statement.
	ShPtr<Variable> tmpVar(cast<Variable>(assignBeforeIf->getLhs()));
	if (!tmpVar) {
		return false;
	}

	// There cannot be any function calls or dereferences in the assign
	// statement before the if statement.
	ShPtr<ValueData> assignBeforeIfData(va->getValueData(assignBeforeIf));
	if (assignBeforeIfData->hasCalls() || assignBeforeIfData->hasDerefs()) {
		return false;
	}

	// The temporary variable cannot be used indirectly.
	if (va->mayBePointed(tmpVar)) {
		return false;
	}

	// If the if statement has no successor, we cannot continue.
	if (!splittedLoop->loopEnd->hasSuccessor()) {
		return false;
	}

	// Check that the variable used in the break condition is assigned to
	// another variable after the if statement.
	ShPtr<AssignStmt> assignAfterIf(cast<AssignStmt>(
		splittedLoop->loopEnd->getSuccessor()));
	if (!assignAfterIf) {
		return false;
	}
	if (tmpVar != assignAfterIf->getRhs()) {
		return false;
	}

	// The temporary variable has to be used only at the three places (apart
	// from its definition).
	ShPtr<VarDefStmt> tmpVarDef;
	ShPtr<VarUses> tmpVarUses(vuv->getUses(tmpVar, currFunc));
	for (const auto &dirUse : tmpVarUses->dirUses) {
		if (dirUse == assignBeforeIf || dirUse == splittedLoop->loopEnd ||
				dirUse == assignAfterIf) {
			continue;
		}

		tmpVarDef = cast<VarDefStmt>(dirUse);
		if (!tmpVarDef || tmpVarDef->getVar() != tmpVar ||
				tmpVarDef->getInitializer()) {
			return false;
		}
	}

	// Optimize the loop. Since the vuv->stmtHasBeenChanged() call below
	// modifies tmpVarUses->dirUses, we have to create a copy of this set and
	// iterate over this copy.
	StmtSet tmpVarDirUses(tmpVarUses->dirUses);
	for (auto &dirUse : tmpVarDirUses) {
		if (dirUse != tmpVarDef) {
			// We have to clone the expression so that there is just a single
			// instance of every expression.
			dirUse->replace(tmpVar,
				ucast<Expression>(assignBeforeIf->getRhs()->clone()));
			va->removeFromCache(dirUse);
			vuv->stmtHasBeenChanged(dirUse, currFunc);
		}
	}
	Statement::removeStatementButKeepDebugComment(assignBeforeIf);
	vuv->stmtHasBeenRemoved(assignBeforeIf, currFunc);
	if (tmpVarDef) {
		removeVarDefOrAssignStatement(tmpVarDef, currFunc);
		vuv->stmtHasBeenRemoved(tmpVarDef, currFunc);
	}

	return true;
}

/**
* @brief Tries the optimization (2) from the class description over the given
*        loop.
*
* @return @c true if the optimization was done, @c false otherwise.
*
* @par Preconditions
*  - @a stmt is a `while True` loop
*/
bool PreWhileTrueLoopConvOptimizer::tryOptimizationCase2(
		ShPtr<WhileLoopStmt> stmt) {

	// Check whether the loop is of the following form:
	//
	//   while True:
	//       ...
	//       tmp = i;
	//       i = tmp + 1;
	//       if (tmp == 100):
	//           break;
	//
	// (Of course, the constants an conditions may be different.)

	// Try to split the loop.
	ShPtr<SplittedWhileTrueLoop> splittedLoop(splitWhileTrueLoop(stmt));
	if (!splittedLoop) {
		return false;
	}

	// If the if statement has none or more than one predecessor, we cannot
	// continue.
	if (splittedLoop->loopEnd->getNumberOfPredecessors() != 1) {
		return false;
	}

	// The statement before the if statement has to be of the form
	//
	//     i = expr
	//
	ShPtr<AssignStmt> assign1BeforeIf(cast<AssignStmt>(
		splittedLoop->loopEnd->getUniquePredecessor()));
	if (!assign1BeforeIf) {
		return false;
	}
	ShPtr<Variable> iVar(cast<Variable>(assign1BeforeIf->getLhs()));
	if (!iVar) {
		return false;
	}

	// Before the assign1BeforeIf statement, there has to be precisely one
	// predecessor.
	if (assign1BeforeIf->getNumberOfPredecessors() != 1) {
		return false;
	}

	// The statement before assign1BeforeIf has to be of the form
	//
	//     tmp = i
	//
	ShPtr<AssignStmt> assign2BeforeIf(cast<AssignStmt>(
		assign1BeforeIf->getUniquePredecessor()));
	if (!assign2BeforeIf) {
		return false;
	}
	ShPtr<Variable> tmpVar(cast<Variable>(assign2BeforeIf->getLhs()));
	if (!tmpVar || assign2BeforeIf->getRhs() != iVar) {
		return false;
	}

	// There cannot be any function calls or dereferences in the statements
	// before the if statement or in its condition.
	ShPtr<ValueData> assign1BeforeIfData(va->getValueData(assign1BeforeIf));
	if (assign1BeforeIfData->hasCalls() || assign1BeforeIfData->hasDerefs()) {
		return false;
	}
	ShPtr<ValueData> assign2BeforeIfData(va->getValueData(assign2BeforeIf));
	if (assign2BeforeIfData->hasCalls() || assign2BeforeIfData->hasDerefs()) {
		return false;
	}
	ShPtr<Expression> ifCond(splittedLoop->loopEnd->getFirstIfCond());
	ShPtr<ValueData> ifCondData(va->getValueData(assign2BeforeIf));
	if (ifCondData->hasCalls() || ifCondData->hasDerefs()) {
		return false;
	}

	// The tmp variable has to be used on the right hand-side of the statement
	// before the if statement and in the if statement's condition.
	if (!assign1BeforeIfData->isDirAccessed(tmpVar) ||
			!ifCondData->isDirAccessed(tmpVar)) {
		return false;
	}

	// The i variable cannot be used on the right-hand side of the statement
	// before the if statement.
	if (assign1BeforeIfData->getDirNumOfUses(iVar) > 1) {
		return false;
	}

	// The temporary variable cannot be used indirectly.
	if (va->mayBePointed(tmpVar)) {
		return false;
	}

	// The temporary variable has to be used only at the three places (apart
	// from its definition).
	ShPtr<VarDefStmt> tmpVarDef;
	// We have to store a copy of tmpVar's dirUses because in the second loop,
	// the original dirUses might be changed, thus invalidating the iterator.
	StmtSet tmpVarDirUses(vuv->getUses(tmpVar, currFunc)->dirUses);
	for (const auto &dirUse : tmpVarDirUses) {
		if (dirUse == assign1BeforeIf || dirUse == assign2BeforeIf ||
				dirUse == splittedLoop->loopEnd) {
			continue;
		}

		tmpVarDef = cast<VarDefStmt>(dirUse);
		if (!tmpVarDef || tmpVarDef->getVar() != tmpVar ||
				tmpVarDef->getInitializer()) {
			return false;
		}
	}

	// Optimize the loop.
	for (auto &dirUse : tmpVarDirUses) {
		if (dirUse != tmpVarDef) {
			dirUse->replace(tmpVar, iVar);
			va->removeFromCache(dirUse);
			vuv->stmtHasBeenChanged(dirUse, currFunc);
		}
	}
	Statement::removeStatementButKeepDebugComment(assign1BeforeIf);
	// We do not have to call `vuv->stmtHasBeenRemoved(assign1BeforeIf,
	// currFunc);` because this statement is appended after the if statement.
	Statement::removeStatementButKeepDebugComment(assign2BeforeIf);
	vuv->stmtHasBeenRemoved(assign2BeforeIf, currFunc);
	if (tmpVarDef) {
		removeVarDefOrAssignStatement(tmpVarDef, currFunc);
		vuv->stmtHasBeenRemoved(tmpVarDef, currFunc);
	}
	splittedLoop->loopEnd->appendStatement(assign1BeforeIf);

	return true;
}

/**
* @brief Tries the optimization (3) from the class description over the given
*        loop.
*
* @return @c true if the optimization was done, @c false otherwise.
*
* @par Preconditions
*  - @a stmt is a `while True` loop
*/
bool PreWhileTrueLoopConvOptimizer::tryOptimizationCase3(
		ShPtr<WhileLoopStmt> stmt) {

	// Check whether the code is of the following form:
	//
	//     i = 0;
	//     if (i >= x):
	//         return
	//     while True:
	//         ...
	//
	// (Of course, the if condition may be different.)

	// There has to be just a single if statement before the loop, no other
	// statements.
	if (stmt->getNumberOfPredecessors() != 1) {
		return false;
	}
	ShPtr<IfStmt> ifBeforeLoop(cast<IfStmt>(stmt->getUniquePredecessor()));
	if (!ifBeforeLoop) {
		return false;
	}

	// The if body has to be a return statement.
	ShPtr<ReturnStmt> returnStmt(cast<ReturnStmt>(skipEmptyStmts(
		ifBeforeLoop->getFirstIfBody())));
	if (!returnStmt) {
		return false;
	}

	// There has to be just a single assign statement before the if statement,
	// no other statements.
	if (ifBeforeLoop->getNumberOfPredecessors() != 1) {
		return false;
	}
	ShPtr<AssignStmt> assignBeforeIf(cast<AssignStmt>(
		ifBeforeLoop->getUniquePredecessor()));
	if (!assignBeforeIf) {
		return false;
	}

	// The assign statment has to be of the form `i = expr`, where expr does
	// not contain i, function calls, or dereferences
	ShPtr<Variable> iVar(cast<Variable>(assignBeforeIf->getLhs()));
	if (!iVar) {
		return false;
	}
	ShPtr<ValueData> assignBeforeIfData(va->getValueData(assignBeforeIf));
	if (assignBeforeIfData->hasCalls() || assignBeforeIfData->hasDerefs() ||
			assignBeforeIfData->getDirNumOfUses(iVar) != 1) {
		return false;
	}

	// The variable i cannot be used in the return statement.
	ShPtr<ValueData> returnStmtData(va->getValueData(returnStmt));
	if (returnStmtData->isDirAccessed(iVar)) {
		return false;
	}

	// The variable i cannot be pointed.
	if (va->mayBePointed(iVar)) {
		return false;
	}

	// Do the optimization.
	// We have to clone the expression so that there is just a single
	// instance of every expression.
	ifBeforeLoop->getFirstIfCond()->replace(iVar,
		ucast<Expression>(assignBeforeIf->getRhs()->clone()));
	va->removeFromCache(ifBeforeLoop);
	vuv->stmtHasBeenChanged(ifBeforeLoop, currFunc);
	Statement::removeStatementButKeepDebugComment(assignBeforeIf);
	// We do not have to call `vuv->stmtHasBeenRemoved(assignBeforeIf,
	// currFunc);` because this statement is appended after the if statement
	// before the loop.
	ifBeforeLoop->appendStatement(assignBeforeIf);

	return true;
}

/**
* @brief Tries the optimization (4) from the class description over the given
*        loop.
*
* @return @c true if the optimization was done, @c false otherwise.
*
* @par Preconditions
*  - @a stmt is a `while True` loop
*/
bool PreWhileTrueLoopConvOptimizer::tryOptimizationCase4(
		ShPtr<WhileLoopStmt> stmt) {

	// Check whether the loop is of the following form:
	//
	//   while True:
	//       ...
	//       tmp = rand()
	//       if (i >= tmp):
	//           break;
	//
	// (Of course, the condition may be different.)

	// Try to split the loop.
	ShPtr<SplittedWhileTrueLoop> splittedLoop(splitWhileTrueLoop(stmt));
	if (!splittedLoop) {
		return false;
	}

	// If the if statement has none or more than one predecessor, we cannot
	// continue.
	if (splittedLoop->loopEnd->getNumberOfPredecessors() != 1) {
		return false;
	}

	// There has to be `tmp = rand()` before the if statement.
	ShPtr<AssignStmt> assignBeforeIf(cast<AssignStmt>(
		splittedLoop->loopEnd->getUniquePredecessor()));
	if (!assignBeforeIf) {
		return false;
	}
	ShPtr<Variable> tmpVar(cast<Variable>(assignBeforeIf->getLhs()));
	if (!tmpVar) {
		return false;
	}
	ShPtr<CallExpr> callExpr(cast<CallExpr>(assignBeforeIf->getRhs()));
	if (!callExpr) {
		return false;
	}

	// The temporary variable has to be used precisely once the if condition.
	ShPtr<ValueData> ifStmtData(va->getValueData(splittedLoop->loopEnd));
	if (ifStmtData->getDirNumOfUses(tmpVar) != 1) {
		return false;
	}

	// The temporary variable cannot be used indirectly.
	if (va->mayBePointed(tmpVar)) {
		return false;
	}

	// There cannot be any function calls or dereferences in the if condition.
	if (ifStmtData->hasCalls() || ifStmtData->hasDerefs()) {
		return false;
	}

	// The if condition cannot be compound. If it is compound, the optimization
	// may be incorrect due to shortcut evaluation.
	// For example, the following situation cannot be optimized:
	//
	//   while True:
	//       ...
	//       tmp = rand()
	//       if (i >= 1 && i <= tmp):
	//           break;
	//
	ShPtr<Expression> ifCond(splittedLoop->loopEnd->getFirstIfCond());
	if (isa<AndOpExpr>(ifCond) || isa<OrOpExpr>(ifCond)) {
		return false;
	}

	// The temporary variable has to be used only at the two places (apart
	// from its definition).
	ShPtr<VarDefStmt> tmpVarDef;
	ShPtr<VarUses> tmpVarUses(vuv->getUses(tmpVar, currFunc));
	for (const auto &dirUse : tmpVarUses->dirUses) {
		if (dirUse == assignBeforeIf || dirUse == splittedLoop->loopEnd) {
			continue;
		}

		tmpVarDef = cast<VarDefStmt>(dirUse);
		if (!tmpVarDef || tmpVarDef->getVar() != tmpVar ||
				tmpVarDef->getInitializer()) {
			return false;
		}
	}

	// Optimize the loop.
	ifCond->replace(tmpVar, callExpr);
	va->removeFromCache(splittedLoop->loopEnd);
	vuv->stmtHasBeenChanged(splittedLoop->loopEnd, currFunc);
	Statement::removeStatementButKeepDebugComment(assignBeforeIf);
	vuv->stmtHasBeenRemoved(assignBeforeIf, currFunc);
	if (tmpVarDef) {
		removeVarDefOrAssignStatement(tmpVarDef, currFunc);
		vuv->stmtHasBeenRemoved(tmpVarDef, currFunc);
	}

	return true;
}

/**
* @brief Tries the optimization (5) from the class description over the given
*        loop.
*
* @return @c true if the optimization was done, @c false otherwise.
*
* @par Preconditions
*  - @a stmt is a `while True` loop
*/
bool PreWhileTrueLoopConvOptimizer::tryOptimizationCase5(
		ShPtr<WhileLoopStmt> stmt) {
	// Check whether the loop is of the following form:
	//
	//   while True:
	//       ...
	//       i = i + 1
	//       if (i > 5):
	//           break
	//
	// (Of course, the condition and constants may be different.)

	// Try to split the loop.
	ShPtr<SplittedWhileTrueLoop> splittedLoop(splitWhileTrueLoop(stmt));
	if (!splittedLoop) {
		return false;
	}

	// If the if statement has none or more than one predecessor, we cannot
	// continue.
	if (splittedLoop->loopEnd->getNumberOfPredecessors() != 1) {
		return false;
	}

	// Check that the variable used in the break condition is assigned before
	// the if statement.
	ShPtr<AssignStmt> assignBeforeIf(cast<AssignStmt>(
		splittedLoop->loopEnd->getUniquePredecessor()));
	if (!assignBeforeIf) {
		return false;
	}
	ShPtr<Variable> iVar(cast<Variable>(assignBeforeIf->getLhs()));
	if (!iVar) {
		return false;
	}

	// There cannot be any function calls or dereferences in the assign
	// statement before the if statement.
	ShPtr<ValueData> assignBeforeIfData(va->getValueData(assignBeforeIf));
	if (assignBeforeIfData->hasCalls() || assignBeforeIfData->hasDerefs()) {
		return false;
	}

	// The variable cannot be used indirectly.
	if (va->mayBePointed(iVar)) {
		return false;
	}

	// The variable has to be used at most on the following places:
	//
	//   i (def)            <-- 1
	//   ...
	//   i = 0              <-- 2
	//   while True:
	//       ...
	//       i = i + 1      <-- 3
	//       if (i > 5):    <-- 4
	//           break
	//
	ShPtr<VarUses> iVarUses(vuv->getUses(iVar, currFunc));
	for (const auto &dirUse : iVarUses->dirUses) {
		if (dirUse == assignBeforeIf || dirUse == splittedLoop->loopEnd ||
				dirUse == stmt->getUniquePredecessor()) {
			continue;
		}

		ShPtr<VarDefStmt> iVarDef(cast<VarDefStmt>(dirUse));
		if (!iVarDef || iVarDef->getVar() != iVar ||
				iVarDef->getInitializer()) {
			// There is some other use of i.
			return false;
		}
	}

	// Optimize the loop.
	splittedLoop->loopEnd->getFirstIfCond()->replace(iVar,
		ucast<Expression>(assignBeforeIf->getRhs()->clone()));
	va->removeFromCache(splittedLoop->loopEnd);
	vuv->stmtHasBeenChanged(splittedLoop->loopEnd, currFunc);
	Statement::removeStatementButKeepDebugComment(assignBeforeIf);
	// We do not have to call `vuv->stmtHasBeenRemoved(assignBeforeIf,
	// currFunc);` because this statement is appended after the if statement.
	splittedLoop->loopEnd->appendStatement(assignBeforeIf);

	return true;
}

} // namespace llvmir2hll
} // namespace retdec
