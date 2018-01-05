/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/equal_operands_sub_optimizer.cpp
* @brief Implementation of EqualOperandsSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/equal_operands_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("EqualOperands", EQUAL_OPERANDS_SUB_OPTIMIZER_ID,
	SubOptimizerFactory, EqualOperandsSubOptimizer::create);

/**
* @brief Constructs the EqualOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
EqualOperandsSubOptimizer::EqualOperandsSubOptimizer(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
EqualOperandsSubOptimizer::~EqualOperandsSubOptimizer() {}

/**
* @brief Creates a new EqualOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> EqualOperandsSubOptimizer::create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new EqualOperandsSubOptimizer(
		arithmExprEvaluator));
}

std::string EqualOperandsSubOptimizer::getId() const {
	return EQUAL_OPERANDS_SUB_OPTIMIZER_ID;
}

void EqualOperandsSubOptimizer::visit(ShPtr<AddOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Optimization like "a + a" -> optimized to "2 * a".
	if ((expr->getFirstOperand())->isEqualTo(expr->getSecondOperand())) {
		ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(
			ConstInt::create(2, 64),
			expr->getSecondOperand()
		));
		optimizeExpr(expr, mulOpExpr);
	}
}

void EqualOperandsSubOptimizer::visit(ShPtr<SubOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Optimization like "a - a" -> optimized to "0".
	if ((expr->getFirstOperand())->isEqualTo(expr->getSecondOperand())) {
		// Due to create correct zero(ConstInt or ConstFloat).
		if (cast<FloatType>(expr->getFirstOperand()->getType())) {
			optimizeExpr(expr, ConstFloat::create(llvm::APFloat(0.0)));
		} else if (ShPtr<IntType> firstOpIntType = cast<IntType>(
				expr->getFirstOperand()->getType())) {
			optimizeExpr(expr, ConstInt::create(0, 64, firstOpIntType->isSigned()));
		}
	}
}

void EqualOperandsSubOptimizer::visit(ShPtr<DivOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Optimization like "a / a" -> optimized to "1".
	if ((expr->getFirstOperand())->isEqualTo(expr->getSecondOperand())) {
		// Due to create correct zero(ConstInt or ConstFloat).
		if (cast<FloatType>(expr->getFirstOperand()->getType())) {
			optimizeExpr(expr, ConstFloat::create(llvm::APFloat(1.0)));
		} else if (ShPtr<IntType> firstOpIntType = cast<IntType>(
				expr->getFirstOperand()->getType())) {
			optimizeExpr(expr, ConstInt::create(1, 64, firstOpIntType->isSigned()));
		}
	}
}

void EqualOperandsSubOptimizer::visit(ShPtr<EqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// We don't want to optimize func() == func() or 2.74 == 2.74.
	if (!isaConstIntOrIntTypeVariable(expr->getFirstOperand())) {
		return;
	}

	// Optimization like "anything == anything" -> optimized to "1(ConstBool)".
	if ((expr->getFirstOperand())->isEqualTo(expr->getSecondOperand())) {
		ShPtr<ConstBool> constBool(ConstBool::create(1));
		optimizeExpr(expr, constBool);
	}
}

void EqualOperandsSubOptimizer::visit(ShPtr<NeqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// We don't want to optimize func() != func() or 2.74 != 2.74.
	if (!isaConstIntOrIntTypeVariable(expr->getFirstOperand())) {
		return;
	}

	// Optimization like "anything != anything" -> optimized to "0(ConstBool)".
	if ((expr->getFirstOperand())->isEqualTo(expr->getSecondOperand())) {
		ShPtr<ConstBool> constBool(ConstBool::create(0));
		optimizeExpr(expr, constBool);
	}
}

/**
* @brief Returns if a @a expr is an @c IntType @c Variable or @c ConstInt.
*
* @param expr An expression to check.
*
* @return @c true if @a expr is an @c IntType @c Variable or @c ConstInt,
*         otherwise @c false.
*/
bool EqualOperandsSubOptimizer::isaConstIntOrIntTypeVariable(
		ShPtr<Expression> expr) {
	if (!isa<IntType>(expr->getType())) {
		return false;
	}

	return isa<ConstInt>(expr) || isa<Variable>(expr);
}

} // namespace llvmir2hll
} // namespace retdec
