/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negative_operand_sub_optimizer.h
* @brief A sub-optimization class that optimize expression with some negative
*        operand.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_NEGATIVE_OPERAND_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_NEGATIVE_OPERAND_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer changes expressions where one of the operands is
*        negative. Examples are mentioned below.
*
* Optimizations are now only on these operators: +, -.
*
* List of performed simplifications (by examples):
*
* @par Operator +
* anything + -(ConstInt/ConstFloat) or (NegOpExpr).
* @code
* return a + -2;
* @endcode
* can be optimized to
* @code
* return a - 2;
* @endcode
* -(ConstInt/ConstFloat) or (NegOpExpr) + anything.
* @code
* return -3 + a;
* @endcode
* can be optimized to
* @code
* return a - 3;
* @endcode
*
* @par Operator -
* Anything - -(ConstInt/ConstFloat) or (NegOpExpr).
* @code
* return a - -2;
* @endcode
* can be optimized to
* @code
* return a + 2;
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class NegativeOperandSubOptimizer final: public SubOptimizer {
public:
	NegativeOperandSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~NegativeOperandSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	/// @}

	ShPtr<ConstFloat> ifNegativeConstFloatReturnIt(ShPtr<Expression> expr) const;
	ShPtr<ConstInt> ifNegativeConstIntReturnIt(ShPtr<Expression> expr) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
