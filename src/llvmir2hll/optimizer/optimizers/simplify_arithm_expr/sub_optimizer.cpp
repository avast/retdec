/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.cpp
* @brief Implementation of SubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs the SubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*
* @par Preconditions
*  - @a arithmExprEvaluator is non-null
*/
SubOptimizer::SubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator):
		arithmExprEvaluator(arithmExprEvaluator) {
	PRECONDITION_NON_NULL(arithmExprEvaluator);
}

/**
* @brief Destructor.
*/
SubOptimizer::~SubOptimizer() {}

/**
* @brief Run optimization and try to optimize.
*
* @param[in] expr An expression to optimize.
*
* @return @c true if something was optimized, otherwise @c false.
*/
bool SubOptimizer::tryOptimize(ShPtr<Expression> expr) {
	return tryOptimizeAndReturnIfCodeChanged(expr);
}

/**
* @brief Optimize expression from @a oldExpr to @a newExpr.
*
* @param[in] oldExpr Old expression that will be replaced.
* @param[in] newExpr New expression that is used to replace @a oldExpr.
*/
void SubOptimizer::optimizeExpr(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) {
	if (oldExpr->isEqualTo(newExpr)) {
		// Nothing to optimize because expressions are same.
		return;
	}

	Expression::replaceExpression(oldExpr, newExpr);
	codeChanged = true;
}

/**
* @brief Start traversal in abstract syntax tree.
*
* @param[in] expr Expression from which the traversal is started.
*
* @return @c true if something was optimized, otherwise @c false.
*/
bool SubOptimizer::tryOptimizeAndReturnIfCodeChanged(ShPtr<Expression> expr) {
	codeChanged = false;
	expr->accept(this);
	return codeChanged;
}

/**
* @brief Check if expression is a @c ConstInt or @c ConstFloat.
*
* @param[in] expr Expression to check.
*
* @return @c true if @a expr is a @c ConstInt or @c ConstFloat, otherwise
*         @c false.
*/
bool SubOptimizer::isConstFloatOrConstInt (ShPtr<Expression> expr) const {
	return isa<ConstInt>(expr) || isa<ConstFloat>(expr);
}

} // namespace llvmir2hll
} // namespace retdec
