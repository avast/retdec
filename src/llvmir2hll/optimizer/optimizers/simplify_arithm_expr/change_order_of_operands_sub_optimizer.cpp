/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/change_order_of_operands_sub_optimizer.cpp
* @brief Implementation of ChangeOrderOfOperandsSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/change_order_of_operands_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("ChangeOrderOfOperands", CHANGE_ORDER_OF_OPERANDS_SUB_OPTIMIZER_ID,
	SubOptimizerFactory, ChangeOrderOfOperandsSubOptimizer::create);

/**
* @brief Constructs the ChangeOrderOfOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ChangeOrderOfOperandsSubOptimizer::ChangeOrderOfOperandsSubOptimizer(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator):
			SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
ChangeOrderOfOperandsSubOptimizer::~ChangeOrderOfOperandsSubOptimizer() {}

/**
* @brief Creates a new ChangeOrderOfOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> ChangeOrderOfOperandsSubOptimizer::create(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new ChangeOrderOfOperandsSubOptimizer(
		arithmExprEvaluator));
}

std::string ChangeOrderOfOperandsSubOptimizer::getId() const {
	return CHANGE_ORDER_OF_OPERANDS_SUB_OPTIMIZER_ID;
}

void ChangeOrderOfOperandsSubOptimizer::visit(ShPtr<MulOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Optimization like "a * 3(ConstInt/ConstFloat)" -> optimized to "3 * a".
	// Need to ensure not to optimize 2 * 3 because this expression will be
	// optimized repeatedly.
	if (!isConstFloatOrConstInt(expr->getFirstOperand()) &&
			isConstFloatOrConstInt(expr->getSecondOperand())) {
		ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(expr->getSecondOperand(),
			expr->getFirstOperand()));
		optimizeExpr(expr, mulOpExpr);
	}
}

} // namespace llvmir2hll
} // namespace retdec
