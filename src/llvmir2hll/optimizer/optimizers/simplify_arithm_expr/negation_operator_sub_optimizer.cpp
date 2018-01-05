/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negation_operator_sub_optimizer.cpp
* @brief Implementation of NegationOperatorSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negation_operator_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("NegationOperator", NEGATION_OPERATOR_SUB_OPTIMIZER_ID,
	SubOptimizerFactory, NegationOperatorSubOptimizer::create);

/**
* @brief Constructs the NegationOperatorSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
NegationOperatorSubOptimizer::NegationOperatorSubOptimizer(ShPtr<
	ArithmExprEvaluator> arithmExprEvaluator):
		SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
NegationOperatorSubOptimizer::~NegationOperatorSubOptimizer() {}

/**
* @brief Creates a new NegationOperatorSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> NegationOperatorSubOptimizer::create(ShPtr<
		ArithmExprEvaluator> arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new NegationOperatorSubOptimizer(
		arithmExprEvaluator));
}

std::string NegationOperatorSubOptimizer::getId() const {
	return NEGATION_OPERATOR_SUB_OPTIMIZER_ID;
}

void NegationOperatorSubOptimizer::visit(ShPtr<NotOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	ShPtr<Expression> negatedExpr(ExpressionNegater::negate(expr->getOperand()));
	// !(a + b) is not optimized to !(a + b) because this is uselessly. Not to
	// optimize expression to the same one is implemented in optimizeExpr(...).
	optimizeExpr(expr, negatedExpr);
}

} // namespace llvmir2hll
} // namespace retdec
