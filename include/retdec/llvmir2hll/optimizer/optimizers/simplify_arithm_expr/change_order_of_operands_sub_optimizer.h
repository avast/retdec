/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/change_order_of_operands_sub_optimizer.h
* @brief A sub-optimization class that change order of operand.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_CHANGE_ORDER_OF_OPERANDS_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_CHANGE_ORDER_OF_OPERANDS_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer changes order of operands. Examples are mentioned below.
*
* Optimizations are now only on these operators: *.
*
* List of performed simplifications (by examples):
*
* @par Operator *
* anything except(ConstInt/ConstFloat) * (ConstInt/ConstFloat).
* @code
* return a * 5;
* @endcode
* can be optimized to
* @code
* return 5 * a;
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class ChangeOrderOfOperandsSubOptimizer final: public SubOptimizer {
public:
	ChangeOrderOfOperandsSubOptimizer(
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~ChangeOrderOfOperandsSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<MulOpExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
