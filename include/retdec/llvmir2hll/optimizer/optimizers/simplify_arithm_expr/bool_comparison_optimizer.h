/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/bool_comparison_optimizer.h
* @brief Simplification of comparisons with @c true and @c false.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_BOOL_COMPARISON_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_BOOL_COMPARISON_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"

namespace retdec {
namespace llvmir2hll {

class ArithmExprEvaluator;

/**
* @brief Simplification of comparisons with @c true and @c false.
*
* This sub-optimizer simplifies comparisons with @c true and @c false by
* transforming the expression so that the comparison is not needed. For example,
* @code
* if (a < 5 == true)
* @endcode
* is simplified to
* @code
* if (a < 5)
* @endcode
* and
* @code
* if (a < 5 == false)
* @endcode
* is simplified to
* @code
* if (a >= 5)
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class BoolComparisonSubOptimizer final: public SubOptimizer {
public:
	BoolComparisonSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~BoolComparisonSubOptimizer() override;

	static ShPtr<SubOptimizer> create(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<EqOpExpr> expr) override;
	virtual void visit(ShPtr<NeqOpExpr> expr) override;
	/// @}

	template<typename ExprType>
	void optimizeNestedComparisons(ExprType expr);

	void replaceWithFirstOperand(ShPtr<BinaryOpExpr> expr);
	void replaceWithNegationOfFirstOperand(ShPtr<BinaryOpExpr> expr);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
