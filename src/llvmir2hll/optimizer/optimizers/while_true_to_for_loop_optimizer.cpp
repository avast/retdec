/**
* @file src/llvmir2hll/optimizer/optimizers/while_true_to_for_loop_optimizer.cpp
* @brief Implementation of WhileTrueToForLoopOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_for_loop_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va Analysis of values.
* @param[in] arithmExprEvaluator Evaluator of expressions.
*
* @par Preconditions
*  - @a module, @a va, and @a arithmExprEvaluator are non-null
*/
WhileTrueToForLoopOptimizer::WhileTrueToForLoopOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<ArithmExprEvaluator> arithmExprEvaluator):
	FuncOptimizer(module), va(va), arithmExprEvaluator(arithmExprEvaluator) {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
		PRECONDITION_NON_NULL(arithmExprEvaluator);
	}

/**
* @brief Destructs the optimizer.
*/
WhileTrueToForLoopOptimizer::~WhileTrueToForLoopOptimizer() {}

void WhileTrueToForLoopOptimizer::doOptimization() {
	if (!va->isInValidState()) {
		va->clearCache();
	}
	FuncOptimizer::doOptimization();

	// Currently, we do not update the used analysis of values (va) during this
	// optimization, so here, at the end of the optimization, we have to put it
	// into an invalid state.
	// TODO Regularly update the cache of va so we do not have to invalidate it.
	//      However, is (or will be) this feasible?
	va->invalidateState();
}

void WhileTrueToForLoopOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Check whether the loop is of the following form:
	// ...
	// i = 0
	// ...
	// while True:
	//     ...
	//     if cond:
	//         break/return
	//     i = i + 1
	//
	// (Of course, the constants 0 and 1 may be different.)

	// Ignore while loops where the condition is not the constant "true".
	if (!isWhileTrueLoop(stmt)) {
		return;
	}

	// Gather information needed to transform the loop, (1) and (2).
	// (1) Parts in the loop, i.e.
	//     ...
	//     if cond:
	//         break/return
	//     i = i + 1
	auto splittedLoop = splitWhileTrueLoop(stmt);
	if (!splittedLoop) {
		// The loop cannot be optimized.
		return;
	}

	// (2) Induction variable before the loop, i.e.
	//   ...
	//   i = 0
	//   ...
	auto indVarInfo = getIndVarInfo(stmt);
	if (!indVarInfo) {
		// The loop cannot be optimized.
		return;
	}

	// Compute the start value.
	auto startValue = computeStartValueOfForLoop(indVarInfo);
	if (!startValue) {
		// The loop cannot be optimized.
		return;
	}

	// Compute the step.
	auto step = computeStepOfForLoop(indVarInfo);
	if (!step) {
		// The loop cannot be optimized.
		return;
	}

	// Compute the end condition.
	auto endCond = computeEndCondOfForLoop(indVarInfo, startValue, step);
	if (!endCond) {
		// The loop cannot be optimized.
		return;
	}

	// Store the last statement of the original loop for later use. Usually,
	// the last empty statement in a "while true" loop contains metadata of the
	// form "continue -> bb". To preserve this piece of information, we store
	// it and use it after the transformation if finished.
	auto lastLoopStmt = Statement::getLastStatement(
		splittedLoop->afterLoopEndStmts
	);
	lastLoopStmt = cast<EmptyStmt>(lastLoopStmt);

	// Remove the initialization of the induction variable.
	Statement::removeStatement(indVarInfo->initStmt);

	// Create the for loop's body. We have to make sure that it is non-empty.
	auto body = splittedLoop->beforeLoopEndStmts;
	if (!body) {
		body = EmptyStmt::create();
	}

	// Create the resulting for loop and replace the original loop with it.
	auto forLoop = ForLoopStmt::create(
		indVarInfo->indVar, startValue, endCond, step, body);
	Statement::replaceStatement(stmt, forLoop);

	// Put lastLoopStmt at the end of the new loop.
	if (lastLoopStmt) {
		Statement::mergeStatements(forLoop->getBody(), lastLoopStmt);
	}

	// If the successors of the resulting for loop are two empty statements
	// with metadata, remove the first one (it usually contains just an end
	// label of the original while loop).
	if (auto forLoopSucc = forLoop->getSuccessor()) {
		if (isa<EmptyStmt>(forLoopSucc) && forLoopSucc->getMetadata() != "") {
			if (auto forLoopSuccSucc = forLoopSucc->getSuccessor()) {
				if (isa<EmptyStmt>(forLoopSuccSucc) &&
						forLoopSuccSucc->getMetadata() != "") {
					Statement::removeStatement(forLoopSucc);
				}
			}
		}
	}

	// TODO What if the exit condition is a return? We should place a return
	//      after the loop.
}

/**
* @brief Returns the start value of the resulting for loop.
*
* If the start value cannot be computed, the null pointer is returned.
*/
ShPtr<Expression> WhileTrueToForLoopOptimizer::computeStartValueOfForLoop(
		ShPtr<IndVarInfo> indVarInfo) const {
	return getRhs(indVarInfo->initStmt);
}

/**
* @brief Returns the end condition of the resulting for loop.
*
* If the end condition cannot be computed, the null pointer is returned.
*
* @par Preconditions
*  - both @a startValue and @a step are non-null
*/
ShPtr<Expression> WhileTrueToForLoopOptimizer::computeEndCondOfForLoop(
		ShPtr<IndVarInfo> indVarInfo,
		ShPtr<Expression> startValue, ShPtr<Expression> step) const {
	PRECONDITION_NON_NULL(startValue);
	PRECONDITION_NON_NULL(step);

	// If the induction variable is not used in the condition, the loop cannot
	// be optimized.
	auto exitCondData = va->getValueData(indVarInfo->exitCond);
	if (!exitCondData->isDirAccessed(indVarInfo->indVar)) {
		return {};
	}

	// The loop's exit condition should be of the form
	//
	//         ... i ... op ...
	//
	//  or
	//
	//         ... op ... i ...
	//
	// where i is the induction variable. For example, i > 10 or i + 2 >= g.

	// First, we need to negate the condition. Recall that if the original end
	// condition is true, the loop should be terminated. However, we need a
	// condition for the loop to be continued.
	auto negatedEndCond = ExpressionNegater::negate(indVarInfo->exitCond);

	// Check whether we support the used operator.
	ShPtr<BinaryOpExpr> endCondOpExpr;
	if (auto ltOpExpr = cast<LtOpExpr>(negatedEndCond)) {
		// <
		endCondOpExpr = ltOpExpr;
	} else if (auto ltEqOpExpr = cast<LtEqOpExpr>(negatedEndCond)) {
		// <=
		endCondOpExpr = ltEqOpExpr;
	} else if (auto neqOpExpr = cast<NeqOpExpr>(negatedEndCond)) {
		// !=
		endCondOpExpr = neqOpExpr;
	} else if (auto gtOpExpr = cast<GtOpExpr>(negatedEndCond)) {
		// >
		endCondOpExpr = gtOpExpr;
	} else if (auto gtEqOpExpr = cast<GtEqOpExpr>(negatedEndCond)) {
		// >=
		endCondOpExpr = gtEqOpExpr;
	} else {
		// Unsupported operator.
		// TODO Add support for more operators.
		return {};
	}

	// We transform the condition to the form
	//
	//             i op ...
	//
	// That is, we need i to be on the left-hand side of the operator.
	// For example, i + 2 < g is transformed into i < g - 2.
	if (endCondOpExpr->getSecondOperand() == indVarInfo->indVar) {
		// ... op i   ->   i inv-op ...
		endCondOpExpr = exchangeCompOpAndOperands(endCondOpExpr);
	} else if (endCondOpExpr->getFirstOperand() != indVarInfo->indVar) {
		// It is a more complex condition.
		if (auto addOpExpr = cast<AddOpExpr>(endCondOpExpr->getFirstOperand())) {
			// i + x op y   ->   i op y - x
			endCondOpExpr->setFirstOperand(indVarInfo->indVar);
			if (addOpExpr->getFirstOperand() == indVarInfo->indVar) {
				endCondOpExpr->setSecondOperand(SubOpExpr::create(
					endCondOpExpr->getSecondOperand(),
					addOpExpr->getSecondOperand()));
			} else if (addOpExpr->getSecondOperand() == indVarInfo->indVar) {
				endCondOpExpr->setSecondOperand(SubOpExpr::create(
					endCondOpExpr->getSecondOperand(),
					addOpExpr->getFirstOperand()));
			} else {
				return {};
			}
		} else if (auto addOpExpr = cast<AddOpExpr>(
				endCondOpExpr->getSecondOperand())) {
			// y op i + x   ->   i inv-op y - x
			endCondOpExpr = exchangeCompOpAndOperands(endCondOpExpr);
			if (addOpExpr->getFirstOperand() == indVarInfo->indVar) {
				endCondOpExpr->setSecondOperand(SubOpExpr::create(
					endCondOpExpr->getSecondOperand(),
					addOpExpr->getSecondOperand()));
			} else if (addOpExpr->getSecondOperand() == indVarInfo->indVar) {
				endCondOpExpr->setSecondOperand(SubOpExpr::create(
					endCondOpExpr->getSecondOperand(),
					addOpExpr->getFirstOperand()));
			} else {
				return {};
			}
			endCondOpExpr->setFirstOperand(indVarInfo->indVar);
		} else if (auto subOpExpr = cast<SubOpExpr>(
				endCondOpExpr->getFirstOperand())) {
			// i - x op y  ->  i op y + x
			endCondOpExpr->setFirstOperand(indVarInfo->indVar);
			if (subOpExpr->getFirstOperand() == indVarInfo->indVar) {
				endCondOpExpr->setSecondOperand(AddOpExpr::create(
					endCondOpExpr->getSecondOperand(),
					subOpExpr->getSecondOperand()));
			} else if (subOpExpr->getSecondOperand() == indVarInfo->indVar) {
				endCondOpExpr->setSecondOperand(AddOpExpr::create(
					endCondOpExpr->getSecondOperand(),
					subOpExpr->getFirstOperand()));
			} else {
				return {};
			}
		} else {
			// TODO Add a more complex handling.
			return {};
		}
	}

	// Now, depending on the exact type of the used operator, create the end
	// condition.
	// TODO Is the used number of bits (32) in the code below correct?
	if (auto ltOpExpr = cast<LtOpExpr>(endCondOpExpr)) {
		// <
		auto endValue = ltOpExpr->getSecondOperand();

		// Since in a "while true" loop, the loop body is entered at least
		// once, we need to add 1 to the end value.
		endValue = AddOpExpr::create(endValue, ConstInt::create(1, 32));

		// The resulting condition is of the form `indVar < endValue`.
		return LtOpExpr::create(indVarInfo->indVar, endValue);
	} else if (auto ltEqOpExpr = cast<LtEqOpExpr>(endCondOpExpr)) {
		// <=
		auto endValue = ltEqOpExpr->getSecondOperand();

		// We convert the operator to <, so add 1 to the end value.
		endValue = AddOpExpr::create(endValue, ConstInt::create(1, 32));

		// Since in a "while true" loop, the loop body is entered at least
		// once, we need to add 1 to the end value.
		endValue = AddOpExpr::create(endValue, ConstInt::create(1, 32));

		// The resulting condition is of the form `indVar < endValue`.
		return LtOpExpr::create(indVarInfo->indVar, endValue);
	} else if (auto gtOpExpr = cast<GtOpExpr>(endCondOpExpr)) {
		// >

		// The resulting condition is of the form `indVar >= endValue` because
		// in a "while true" loop, the loop body is entered at least once, so
		// we have to subtract 1 from the end value. This can be done by
		// replacing > with >=.
		return GtEqOpExpr::create(gtOpExpr->getFirstOperand(),
			gtOpExpr->getSecondOperand());
	} else if (auto gtEqOpExpr = cast<GtEqOpExpr>(endCondOpExpr)) {
		// >=

		// The resulting condition is of the form `indVar >= endValue - 1`
		// because in a "while true" loop, the loop body is entered at least
		// once.
		return GtEqOpExpr::create(
			gtEqOpExpr->getFirstOperand(),
			SubOpExpr::create(
				gtEqOpExpr->getSecondOperand(),
				ConstInt::create(1, 32)
			)
		);
	} else if (auto neqOpExpr = cast<NeqOpExpr>(endCondOpExpr)) {
		// !=
		auto endValue = neqOpExpr->getSecondOperand();

		// We try to convert the operator to <. Before that, however, we have
		// to check whether it is possible, depending on the value of step.
		if (isNonNegative(step)) {
			// step >= 0

			// Check that startValue < endValue
			auto evalStartValue = evaluate(startValue);
			auto evalEndValue = evaluate(endValue);
			if (!evalStartValue || !evalEndValue ||
					evalStartValue->getValue() >= evalEndValue->getValue()) {
				return {};
			}

			// Since in a "while true" loop, the loop body is entered at least
			// once, we need to add 1 to the end value.
			endValue = AddOpExpr::create(endValue, ConstInt::create(1, 32));

			// The resulting condition is of the form `indVar < endValue`.
			return LtOpExpr::create(indVarInfo->indVar, endValue);
		}

		// step < 0

		// Check that startValue > endValue
		auto evalStartValue = evaluate(startValue);
		auto evalEndValue = evaluate(endValue);
		if (!evalStartValue || !evalEndValue ||
				evalStartValue->getValue() < evalEndValue->getValue()) {
			return {};
		}

		// Since in a "while true" loop, the loop body is entered at least
		// once, we need to subtract 1 from the end value.
		endValue = SubOpExpr::create(endValue, ConstInt::create(1, 32));

		// The resulting condition is of the form `indVar > endValue`.
		return GtOpExpr::create(indVarInfo->indVar, endValue);
	}

	// After the conversion, we have obtained an unsupported operator, so we
	// cannot create a proper end condition.
	// TODO Add a more complex handling of the conditions.
	return {};
}

/**
* @brief Returns the step of the resulting for loop.
*
* If the step cannot be computed, the null pointer is returned.
*/
ShPtr<Expression> WhileTrueToForLoopOptimizer::computeStepOfForLoop(
		ShPtr<IndVarInfo> indVarInfo) const {
	auto assignStmt = cast<AssignStmt>(indVarInfo->updateStmt);
	if (!assignStmt) {
		return {};
	}

	auto updateRhs = assignStmt->getRhs();
	if (auto addOpExpr = cast<AddOpExpr>(updateRhs)) {
		// i = i + x
		if (addOpExpr->getFirstOperand() == indVarInfo->indVar) {
			return addOpExpr->getSecondOperand();
		// i = x + i
		} else if (addOpExpr->getSecondOperand() == indVarInfo->indVar) {
			return addOpExpr->getFirstOperand();
		}
	} else if (auto subOpExpr = cast<SubOpExpr>(updateRhs)) {
		// i = i - x
		if (subOpExpr->getFirstOperand() == indVarInfo->indVar) {
			auto secOp = subOpExpr->getSecondOperand();
			if (auto constInt = cast<ConstInt>(secOp)) {
				// x is a constant, so we may directly invert it.
				return ConstInt::create(-constInt->getValue());
			}
			// x is not a constant, so return -(x).
			return NegOpExpr::create(secOp);
		}
	}
	// TODO Are there more possibilities? Use some design pattern instead?

	return {};
}

/**
* @brief Tries to evaluate the given arithmetical expression and returns the
*        resulting value.
*
* If the expression cannot be evaluated, the null pointer is returned.
*/
ShPtr<ConstInt> WhileTrueToForLoopOptimizer::evaluate(ShPtr<Expression> expr) const {
	auto evaluated = arithmExprEvaluator->evaluate(expr);
	return cast<ConstInt>(evaluated);
}

/**
* @brief Exchanges the operation and operands in the given binary comparison
*        expression.
*
* For example, `i < j` is converted into `j > i`.
*
* The original expression is not modified.
*
* If the operation is is not comparison, it returns the null pointer.
*/
ShPtr<BinaryOpExpr> WhileTrueToForLoopOptimizer::exchangeCompOpAndOperands(
		ShPtr<BinaryOpExpr> expr) {
	if (isa<GtOpExpr>(expr)) {
		// x > y  ->  y < x
		return LtOpExpr::create(
			expr->getSecondOperand(), expr->getFirstOperand());
	} else if (isa<LtOpExpr>(expr)) {
		// x < y  ->  y > x
		return GtOpExpr::create(
			expr->getSecondOperand(), expr->getFirstOperand());
	} else if (isa<LtEqOpExpr>(expr)) {
		// x <= y  ->  y >= x
		return GtEqOpExpr::create(
			expr->getSecondOperand(), expr->getFirstOperand());
	} else if (isa<GtEqOpExpr>(expr)) {
		// x >= y  ->  y <= x
		return LtEqOpExpr::create(
			expr->getSecondOperand(), expr->getFirstOperand());
	} else if (isa<EqOpExpr>(expr)) {
		// x == y  ->  y == x
		return EqOpExpr::create(
			expr->getSecondOperand(), expr->getFirstOperand());
	} else if (isa<NeqOpExpr>(expr)) {
		// x != y  -> y != x
		return NeqOpExpr::create(
			expr->getSecondOperand(), expr->getFirstOperand());
	}

	// Not a comparison operator.
	return {};
}

/**
* @brief Returns @c true if the given expression represents a non-negative
*        value, @c false otherwise.
*
* If the non-negativeness of @a expr cannot be determined, this function
* returns @c false.
*/
bool WhileTrueToForLoopOptimizer::isNonNegative(ShPtr<Expression> expr) {
	// Constant integer.
	if (auto constInt = cast<ConstInt>(expr)) {
		return constInt->isZero() || constInt->isPositive();
	}

	// TODO What about other possibilities?

	// Unknown.
	return false;
}

/**
* @brief Returns @c true if the given expression represents a positive value,
*        @c false otherwise.
*
* If the positiveness of @a expr cannot be determined, this function
* returns @c false.
*/
bool WhileTrueToForLoopOptimizer::isPositive(ShPtr<Expression> expr) {
	// Constant integer.
	if (auto constInt = cast<ConstInt>(expr)) {
		return constInt->isPositive();
	}

	// TODO What about other possibilities?

	// Unknown.
	return false;
}

} // namespace llvmir2hll
} // namespace retdec
