/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/bool_comparison_optimizer.cpp
* @brief Implementation of BoolComparisonSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/bool_comparison_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer_factory.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("BoolComparison", BOOL_COMPARISON_OPTIMIZER_ID,
	SubOptimizerFactory, BoolComparisonSubOptimizer::create);

/**
* @brief Constructs the sub-optimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
BoolComparisonSubOptimizer::BoolComparisonSubOptimizer(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructs the sub-optimizer.
*/
BoolComparisonSubOptimizer::~BoolComparisonSubOptimizer() {}

/**
* @brief Creates a new sub-optimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> BoolComparisonSubOptimizer::create(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator) {
	return std::make_shared<BoolComparisonSubOptimizer>(arithmExprEvaluator);
}

std::string BoolComparisonSubOptimizer::getId() const {
	return BOOL_COMPARISON_OPTIMIZER_ID;
}

void BoolComparisonSubOptimizer::visit(ShPtr<EqOpExpr> expr) {
	optimizeNestedComparisons(expr);

	auto secOpBool = cast<ConstBool>(expr->getSecondOperand());
	if (!secOpBool) {
		return;
	}

	// Optimize
	//
	//    EXPR == true
	//
	// to
	//
	//    EXPR
	if (secOpBool->isTrue()) {
		replaceWithFirstOperand(expr);
		return;
	}

	// Optimize
	//
	//    EXPR == false
	//
	// to
	//
	//    !EXPR
	if (secOpBool->isFalse()) {
		replaceWithNegationOfFirstOperand(expr);
		return;
	}
}

void BoolComparisonSubOptimizer::visit(ShPtr<NeqOpExpr> expr) {
	optimizeNestedComparisons(expr);

	auto secOpBool = cast<ConstBool>(expr->getSecondOperand());
	if (!secOpBool) {
		return;
	}

	// Optimize
	//
	//    EXPR != true
	//
	// to
	//
	//    !EXPR
	if (secOpBool->isTrue()) {
		replaceWithNegationOfFirstOperand(expr);
		return;
	}

	// Optimize
	//
	//    EXPR != false
	//
	// to
	//
	//    EXPR
	if (secOpBool->isFalse()) {
		replaceWithFirstOperand(expr);
		return;
	}
}

template<typename ExprType>
void BoolComparisonSubOptimizer::optimizeNestedComparisons(ExprType expr) {
	SubOptimizer::visit(expr);
}

void BoolComparisonSubOptimizer::replaceWithFirstOperand(ShPtr<BinaryOpExpr> expr) {
	Expression::replaceExpression(expr, expr->getFirstOperand());
}

void BoolComparisonSubOptimizer::replaceWithNegationOfFirstOperand(
		ShPtr<BinaryOpExpr> expr) {
	Expression::replaceExpression(
		expr,
		ExpressionNegater::negate(expr->getFirstOperand())
	);
}

} // namespace llvmir2hll
} // namespace retdec
