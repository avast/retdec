/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/ternary_operator_sub_optimizer.cpp
* @brief Implementation of TernaryOperatorSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/ternary_operator_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("TernaryOperator", TERNARY_OPERATOR_SUB_OPTIMIZER_ID,
	SubOptimizerFactory, TernaryOperatorSubOptimizer::create);

/**
* @brief Constructs the TernaryOperatorSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
TernaryOperatorSubOptimizer::TernaryOperatorSubOptimizer(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator):
			SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
TernaryOperatorSubOptimizer::~TernaryOperatorSubOptimizer() {}

/**
* @brief Creates a new TernaryOperatorSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> TernaryOperatorSubOptimizer::create(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new TernaryOperatorSubOptimizer(
		arithmExprEvaluator));
}

std::string TernaryOperatorSubOptimizer::getId() const {
	return TERNARY_OPERATOR_SUB_OPTIMIZER_ID;
}

void TernaryOperatorSubOptimizer::visit(ShPtr<TernaryOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	ShPtr<ConstBool> constBool(cast<ConstBool>(expr->getCondition()));
	if (!constBool) {
		return;
	}

	if (constBool->getValue()) {
		// True in the condition.
		optimizeExpr(expr, expr->getTrueValue());
	} else {
		// False in the condition.
		optimizeExpr(expr, expr->getFalseValue());
	}
}

} // namespace llvmir2hll
} // namespace retdec
