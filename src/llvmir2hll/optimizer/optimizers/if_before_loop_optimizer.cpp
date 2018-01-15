/**
* @file src/llvmir2hll/optimizer/optimizers/if_before_loop_optimizer.cpp
* @brief Implementation of IfBeforeLoopOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_before_loop_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

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
IfBeforeLoopOptimizer::IfBeforeLoopOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va):
	FuncOptimizer(module), va(va) {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
	}

/**
* @brief Destructs the optimizer.
*/
IfBeforeLoopOptimizer::~IfBeforeLoopOptimizer() {}

void IfBeforeLoopOptimizer::doOptimization() {
	if (!va->isInValidState()) {
		va->clearCache();
	}
	FuncOptimizer::doOptimization();

	// Currently, we do not update the used analysis of values (va) during this
	// optimization, so here, at the end of the optimization, we have to put it
	// into an invalid state.
	// TODO Regularly update the cache of va so we do not have to invalidate it.
	va->invalidateState();
}

void IfBeforeLoopOptimizer::visit(ShPtr<IfStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// TODO What if the if statement is necessary, i.e. this is not the case
	//      when it can be optimized? Add some more checks. Perhaps an
	//      evaluator of expressions will be necessary.
	if (tryOptimizationCase1(stmt)) {
		return;
	}
	if (tryOptimizationCase2(stmt)) {
		return;
	}
	// More optimizations can be put here.
}

/**
* @brief Tries the optimization (1) from the class description over the given
*        if statement.
*
* @return @c true if the optimization was done, @c false otherwise.
*/
bool IfBeforeLoopOptimizer::tryOptimizationCase1(ShPtr<IfStmt> stmt) {
	// Check that the code surrounding the if statement is of the following
	// form:
	//
	//     if cond: // cond uses a variable x
	//        for loop // the end value of the loop depends on x
	//            ... // the loop's body
	//     ... // some statements
	//
	// TODO What about "while cond" loops instead of for loops?
	ShPtr<Expression> ifCond(stmt->getFirstIfCond());
	ShPtr<ValueData> ifCondData(va->getValueData(ifCond));

	// Check that the if's condition is of the form x op y,
	// where y is a constant and x is a variable (or vice versa, but in what
	// follows, x denotes a variable).
	ShPtr<BinaryOpExpr> ifCondOp(cast<BinaryOpExpr>(ifCond));
	if (!ifCondOp) {
		// This if statement cannot be optimized.
		return false;
	}
	if (ifCondData->getNumOfDirAccessedVars() != 1) {
		// There should be only a single variable in the if's condition.
		return false;
	}
	const VarSet &allVarsUsedInIfCond(ifCondData->getDirAccessedVars());
	ShPtr<Variable> x(*allVarsUsedInIfCond.begin());
	if (cast<Variable>(ifCondOp->getFirstOperand()) != x &&
		cast<Variable>(ifCondOp->getSecondOperand()) != x) {
		// One operand of ifCondOp has to be x.
		return false;
	}
	if (!isa<ConstInt>(ifCondOp->getFirstOperand()) &&
			!isa<ConstInt>(ifCondOp->getSecondOperand()) &&
			!isa<ConstFloat>(ifCondOp->getFirstOperand()) &&
			!isa<ConstFloat>(ifCondOp->getSecondOperand())) {
		// The other operand of ifCondOp has to be a constant.
		return false;
	}

	// Check that the if's body starts with a for loop.
	ShPtr<ForLoopStmt> forLoop(cast<ForLoopStmt>(skipEmptyStmts(
		stmt->getFirstIfBody())));
	if (!forLoop) {
		// This if statement cannot be optimized.
		return false;
	}

	// Check that the end value of forLoop depends on x.
	ShPtr<ValueData> loopEndData(va->getValueData(forLoop->getEndCond()));
	if (!loopEndData->isDirAccessed(x)) {
		// This if statement cannot be optimized.
		return false;
	}

	// Check that there are no statements after forLoop (with the exception
	// of empty statements).
	// TODO What if there are some statements? Can't we optimize it anyway?
	if (skipEmptyStmts(forLoop->getSuccessor())) {
		// There is a non-empty statement after forLoop.
		return false;
	}

	//
	// Optimize the if statement.
	//

	// Remove the last empty statement after forLoop (it usually contains just
	// a debug comment of the form "branch -> bb"). Notice that now, the
	// successor of forLoop can be either an empty statement or the null
	// pointer.
	if (ShPtr<Statement> forLoopSucc = forLoop->getSuccessor()) {
		Statement::removeStatement(forLoopSucc);
	}

	// Store metadata attached to the if statement.
	std::string ifStmtMetadata(stmt->getMetadata());

	// Remove the surrounding if statement.
	ShPtr<Statement> ifStmtReplacement(stmt->getFirstIfBody());
	Statement::replaceStatement(stmt, ifStmtReplacement);

	// Attach the if's metadata to forLoop (if any). However, put them in an
	// empty statement because there could already be some existing metadata.
	if (!ifStmtMetadata.empty()) {
		ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
		emptyStmt->setMetadata(ifStmtMetadata);
		ifStmtReplacement->prependStatement(emptyStmt);
	}

	return true;
}

/**
* @brief Tries the optimization (2) from the class description over the given
*        if statement.
*
* @return @c true if the optimization was done, @c false otherwise.
*/
bool IfBeforeLoopOptimizer::tryOptimizationCase2(ShPtr<IfStmt> stmt) {
	// Check that the code surrounding the if statement is of the following
	// form:
	//
	//     if cond: // cond uses a variable x
	//         return
	//     for loop // the end value of the loop depends on x
	//         ...
	//
	// TODO What about "while cond" loops instead of for loops?

	// Get the variable x.
	ShPtr<Expression> ifCond(stmt->getFirstIfCond());
	ShPtr<ValueData> ifCondData(va->getValueData(ifCond));
	if (ifCondData->getNumOfDirAccessedVars() != 1) {
		// There should be only a single variable in the if's condition.
		return false;
	}
	const VarSet &allVarsUsedInIfCond(ifCondData->getDirAccessedVars());
	ShPtr<Variable> x(*allVarsUsedInIfCond.begin());
	if (!x) {
		// The variable x was not found.
		return false;
	}

	// Check that the if's successor is a for loop.
	ShPtr<ForLoopStmt> forLoop(cast<ForLoopStmt>(skipEmptyStmts(
		stmt->getSuccessor())));
	if (!forLoop) {
		return false;
	}

	// Check that the end value of forLoop depends on x.
	ShPtr<ValueData> loopEndData(va->getValueData(forLoop->getEndCond()));
	if (!loopEndData->isDirAccessed(x)) {
		return false;
	}

	// Optimize the if statement.
	Statement::removeStatementButKeepDebugComment(stmt);

	return true;
}

} // namespace llvmir2hll
} // namespace retdec
