/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negation_operator_sub_optimizer.h
* @brief A sub-optimization class that optimizes negation operators outside of
*        expressions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_NEGATION_OPERATOR_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_NEGATION_OPERATOR_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer optimizes negation operators outside of expressions.
*
* Optimization is on the NegOpExpr operator (i.e. @c ! in C).
*
* List of performed simplifications (by examples):
*
* @par Operator !
* @code
* if (!(legume == 0 || legume > 4)) {...}
* @endcode
* can be optimized to
* @code
* if (legume != 0 && legume <= 4)) {...}
* @endcode
* or
* @code
* if (!(legume == 0 && legume > 4)) {...}
* @endcode
* can be optimized to
* @code
* if (legume != 0 || legume <= 4)) {...}
* @endcode
* or
* @code
* a = !!a
* @endcode
* can be optimized to
* @code
* a = a
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class NegationOperatorSubOptimizer final: public SubOptimizer {
public:
	NegationOperatorSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~NegationOperatorSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<NotOpExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
