/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/zero_sub_optimizer.cpp
* @brief Implementation of ZeroSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/zero_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("Zero", ZERO_SUB_OPTIMIZER_ID, SubOptimizerFactory,
	ZeroSubOptimizer::create);

/**
* @brief Constructs the ZeroSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ZeroSubOptimizer::ZeroSubOptimizer(ArithmExprEvaluator*
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Creates a new ZeroSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
SubOptimizer* ZeroSubOptimizer::create(ArithmExprEvaluator*
		arithmExprEvaluator) {
	return new ZeroSubOptimizer(arithmExprEvaluator);
}

std::string ZeroSubOptimizer::getId() const {
	return ZERO_SUB_OPTIMIZER_ID;
}

void ZeroSubOptimizer::visit(AddOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) + a -> optimized to "a".
		optimizeExpr(expr, expr->getSecondOperand());
	} else if (isOpZero(expr->getSecondOperand())) {
		// Optimization like a + 0(ConstFloat/ConstInt) -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void ZeroSubOptimizer::visit(SubOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	ConstInt* secOpConstInt(cast<ConstInt>(expr->getSecondOperand()));
	ConstFloat* secOpConstFloat(cast<ConstFloat>(expr->getSecondOperand()));
	NegOpExpr* secOpNegOpExpr(cast<NegOpExpr>(expr->getSecondOperand()));

	// Optimization like "0(ConstInt/ConstFloat) - anything -> optimized to
	// "-anything"
	if (isOpZero(expr->getFirstOperand())) {
		if (secOpConstInt && secOpConstInt->isSigned()) {
			// Optimization like "0.0 - 1" -> optimized to "-1"
			secOpConstInt->flipSign();
			optimizeExpr(expr, secOpConstInt);
		} else if (secOpConstFloat) {
			// Optimization like "0 - 2.0" -> optimized to "-2.0".
			secOpConstFloat->flipSign();
			optimizeExpr(expr, secOpConstFloat);
		} else if (secOpNegOpExpr) {
			// Optimization like "0 - -a" -> optimized to "a"
			optimizeExpr(expr, secOpNegOpExpr->getOperand());
		} else {
			// Optimization like "0 - a" -> optimized to "-a"
			NegOpExpr* newNegOpExpr(NegOpExpr::create(
				expr->getSecondOperand()));
			optimizeExpr(expr, newNegOpExpr);
		}
	}

	// Optimization like "anything - 0(ConstInt/ConstFloat)" -> optimized to
	// "anything"
	if (isOpZero(expr->getSecondOperand())) {
		optimizeExpr(expr, expr->getFirstOperand());
		return;
	}
}

void ZeroSubOptimizer::visit(MulOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) * a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	} else if (isOpZero(expr->getSecondOperand())) {
		// Optimization like a * 0(ConstFloat/ConstInt) -> optimized to "0".
		optimizeExpr(expr, expr->getSecondOperand());
	}
}

void ZeroSubOptimizer::visit(DivOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) / a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void ZeroSubOptimizer::visit(ModOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) % a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void ZeroSubOptimizer::visit(BitAndOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isConstIntZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) & a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	} else if (isConstIntZero(expr->getSecondOperand())) {
		// Optimization like a & 0(ConstFloat/ConstInt) -> optimized to "0".
		optimizeExpr(expr, expr->getSecondOperand());
	}
}

void ZeroSubOptimizer::visit(BitOrOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isConstIntZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) | a -> optimized to "a".
		optimizeExpr(expr, expr->getSecondOperand());
	} else if (isConstIntZero(expr->getSecondOperand())) {
		// Optimization like a | 0(ConstFloat/ConstInt) -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}

}

void ZeroSubOptimizer::visit(BitXorOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (isConstIntZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) ^ a -> optimized to "a".
		optimizeExpr(expr, expr->getSecondOperand());
	} else if (isConstIntZero(expr->getSecondOperand())) {
		// Optimization like a ^ 0(ConstFloat/ConstInt) -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

/**
* @brief Check if expression is a @c ConstInt zero.
*
* @param[in] expr Expression to check.
* @return @c true if @a expr is a @c ConstInt zero, otherwise @c false.
*/
bool ZeroSubOptimizer::isConstIntZero(Expression* expr) const {
	ConstInt* opConstInt(cast<ConstInt>(expr));
	return opConstInt && opConstInt->isZero();
}

/**
* @brief Check if expression is a @c ConstFloat zero.
*
* @param[in] expr Expression to check.
* @return @c true if @a expr is a @c ConstFloat zero, otherwise @c false.
*/
bool ZeroSubOptimizer::isConstFloatZero(Expression* expr) const {
	ConstFloat* opConstFloat(cast<ConstFloat>(expr));
	return opConstFloat && opConstFloat->isZero();
}

/**
* @brief Check if expression is a @c ConstInt or @c ConstFloat zero.
*
* @param[in] expr Expression to check.
* @return @c true if @a expr is a @c ConstInt or @c ConstFloat zero,
*         otherwise @c false.
*/
bool ZeroSubOptimizer::isOpZero(Expression* expr) const {
	return isConstIntZero(expr) || isConstFloatZero(expr);
}

} // namespace llvmir2hll
} // namespace retdec
