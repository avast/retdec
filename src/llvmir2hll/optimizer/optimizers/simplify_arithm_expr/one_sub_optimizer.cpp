/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/one_sub_optimizer.cpp
* @brief Implementation of a sub-optimization class that optimize expression
*        with operand which is number one.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/one_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("One", ONE_SUB_OPTIMIZER_ID, SubOptimizerFactory,
	OneSubOptimizer::create);

/**
* @brief Constructs the OneSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
OneSubOptimizer::OneSubOptimizer(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
OneSubOptimizer::~OneSubOptimizer() {}

/**
* @brief Creates a new OneSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> OneSubOptimizer::create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new OneSubOptimizer(arithmExprEvaluator));
}

std::string OneSubOptimizer::getId() const {
	return ONE_SUB_OPTIMIZER_ID;
}

void OneSubOptimizer::visit(ShPtr<MulOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpOne(expr->getFirstOperand())) {
		// Optimization like "1(ConstInt/ConstFloat) * a" -> optimized to "a".
		optimizeExpr(expr, expr->getSecondOperand());
	} else if (isOpOne(expr->getSecondOperand())) {
		// Optimization like "a * 1(ConstInt/ConstFloat)" -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void OneSubOptimizer::visit(ShPtr<DivOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isOpOne(expr->getSecondOperand())) {
		// Optimization like "a / 1(ConstInt/ConstFloat)" -> optimized to "a".
		optimizeExpr(expr, expr->getFirstOperand());
	}
}

void OneSubOptimizer::visit(ShPtr<BitXorOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (isConstIntOne(expr->getFirstOperand())) {
		// Optimization like "1 ^ (a == b)" -> optimized to "a != b" or
		// optimization like 1 ^ someCasts(a == b) -> optimized to "a != b."
		ShPtr<Expression> tempExpr(expr->getSecondOperand());
		// Go through casts.
		while (isa<CastExpr>(tempExpr)) {
			tempExpr = cast<CastExpr>(tempExpr)->getOperand();
		}
		ShPtr<EqOpExpr> eqOpExpr(cast<EqOpExpr>(tempExpr));
		if (eqOpExpr) {
			// The second operand must be EqOpExpr.
			ShPtr<NeqOpExpr> neqOpExpr(
				NeqOpExpr::create(
					eqOpExpr->getFirstOperand(),
					eqOpExpr->getSecondOperand()
			));
			optimizeExpr(expr, neqOpExpr);
			return;
		}
	}

	if (isConstIntOne(expr->getSecondOperand())) {
		// Optimization like "(a == b) ^ 1" -> optimized to "a != b" or
		// optimization like someCasts(a == b) ^ 1 -> optimized to "a != b."
		ShPtr<Expression> tempExpr(expr->getFirstOperand());
		// Go through casts.
		while (isa<CastExpr>(tempExpr)) {
			tempExpr = cast<CastExpr>(tempExpr)->getOperand();
		}
		ShPtr<EqOpExpr> eqOpExpr(cast<EqOpExpr>(tempExpr));
		if (eqOpExpr) {
			// The first operand must be EqOpExpr.
			ShPtr<NeqOpExpr> neqOpExpr(
				NeqOpExpr::create(
					eqOpExpr->getFirstOperand(),
					eqOpExpr->getSecondOperand()
			));
			optimizeExpr(expr, neqOpExpr);
			return;
		}
	}
}

/**
* @brief Determines whether the float constant has the value @c 1.0.
*
* @param[in] value A value to check.
*
* @return @c true if @a value is a float constant with the value @c 1.0,
*         otherwise @c false.
*/
bool OneSubOptimizer::isOne(ShPtr<ConstFloat> value) const {
	return value->isEqualTo(ConstFloat::create(llvm::APFloat(value->getValue().
		getSemantics(), "1.0")));
}

/**
* @brief Determines whether the constant integer has the value @c 1.
*
* @param[in] value A value to check.
*
* @return @c true if @a value is a constant integer with the value @c 1,
*         otherwise @c false.
*/
bool OneSubOptimizer::isOne(ShPtr<ConstInt> value) const {
	return value->isEqualTo(ConstInt::create(1, value->getValue().getBitWidth()));
}

/**
* @brief Check if expression is a @c ConstInt one.
*
* @param[in] expr Expression to check.
*
* @return @c true if @a expr is a @c ConstInt one, otherwise @c false.
*/
bool OneSubOptimizer::isConstIntOne(ShPtr<Expression> expr) const {
	ShPtr<ConstInt> opConstInt(cast<ConstInt>(expr));
	return opConstInt && isOne(opConstInt);
}

/**
* @brief Check if expression is a @c ConstFloat one.
*
* @param[in] expr Expression to check.
*
* @return @c true if @a expr is a @c ConstFloat one, otherwise @c false.
*/
bool OneSubOptimizer::isConstFloatOne(ShPtr<Expression> expr) const {
	ShPtr<ConstFloat> opConstFloat(cast<ConstFloat>(expr));
	return opConstFloat && isOne(opConstFloat);
}

/**
* @brief Check if expression is a @c ConstInt or @c ConstFloat number one.
*
* @param[in] expr Expression to check.
*
* @return @c true if @a expr is a @c ConstInt or @c ConstFloat one,
*         otherwise @c false.
*/
bool OneSubOptimizer::isOpOne(ShPtr<Expression> expr) const {
	return isConstIntOne(expr) || isConstFloatOne(expr);
}

} // namespace llvmir2hll
} // namespace retdec
