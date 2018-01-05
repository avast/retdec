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
ZeroSubOptimizer::ZeroSubOptimizer(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
ZeroSubOptimizer::~ZeroSubOptimizer() {}

/**
* @brief Creates a new ZeroSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> ZeroSubOptimizer::create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new ZeroSubOptimizer(arithmExprEvaluator));
}

std::string ZeroSubOptimizer::getId() const {
	return ZERO_SUB_OPTIMIZER_ID;
}

void ZeroSubOptimizer::visit(ShPtr<AddOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) + a -> optimized to "a".
		optimizeExpr(expr, expr->getSecondOperand());
	} else if (isOpZero(expr->getSecondOperand())) {
		// Optimization like a + 0(ConstFloat/ConstInt) -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void ZeroSubOptimizer::visit(ShPtr<SubOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	ShPtr<ConstInt> secOpConstInt(cast<ConstInt>(expr->getSecondOperand()));
	ShPtr<ConstFloat> secOpConstFloat(cast<ConstFloat>(expr->getSecondOperand()));
	ShPtr<NegOpExpr> secOpNegOpExpr(cast<NegOpExpr>(expr->getSecondOperand()));

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
			ShPtr<NegOpExpr> newNegOpExpr(NegOpExpr::create(
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

void ZeroSubOptimizer::visit(ShPtr<MulOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) * a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	} else if (isOpZero(expr->getSecondOperand())) {
		// Optimization like a * 0(ConstFloat/ConstInt) -> optimized to "0".
		optimizeExpr(expr, expr->getSecondOperand());
	}
}

void ZeroSubOptimizer::visit(ShPtr<DivOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) / a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void ZeroSubOptimizer::visit(ShPtr<ModOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) % a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void ZeroSubOptimizer::visit(ShPtr<BitAndOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isConstIntZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) & a -> optimized to "0".
		optimizeExpr(expr, expr->getFirstOperand());
	} else if (isConstIntZero(expr->getSecondOperand())) {
		// Optimization like a & 0(ConstFloat/ConstInt) -> optimized to "0".
		optimizeExpr(expr, expr->getSecondOperand());
	}
}

void ZeroSubOptimizer::visit(ShPtr<BitOrOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isConstIntZero(expr->getFirstOperand())) {
		// Optimization like 0(ConstFloat/ConstInt) | a -> optimized to "a".
		optimizeExpr(expr, expr->getSecondOperand());
	} else if (isConstIntZero(expr->getSecondOperand())) {
		// Optimization like a | 0(ConstFloat/ConstInt) -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}

}

void ZeroSubOptimizer::visit(ShPtr<BitXorOpExpr> expr) {
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
bool ZeroSubOptimizer::isConstIntZero(ShPtr<Expression> expr) const {
	ShPtr<ConstInt> opConstInt(cast<ConstInt>(expr));
	return opConstInt && opConstInt->isZero();
}

/**
* @brief Check if expression is a @c ConstFloat zero.
*
* @param[in] expr Expression to check.
* @return @c true if @a expr is a @c ConstFloat zero, otherwise @c false.
*/
bool ZeroSubOptimizer::isConstFloatZero(ShPtr<Expression> expr) const {
	ShPtr<ConstFloat> opConstFloat(cast<ConstFloat>(expr));
	return opConstFloat && opConstFloat->isZero();
}

/**
* @brief Check if expression is a @c ConstInt or @c ConstFloat zero.
*
* @param[in] expr Expression to check.
* @return @c true if @a expr is a @c ConstInt or @c ConstFloat zero,
*         otherwise @c false.
*/
bool ZeroSubOptimizer::isOpZero(ShPtr<Expression> expr) const {
	return isConstIntZero(expr) || isConstFloatZero(expr);
}

} // namespace llvmir2hll
} // namespace retdec
