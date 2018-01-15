/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/one_sub_optimizer.h
* @brief A sub-optimization class that optimize expression with number one operand.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_ONE_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_ONE_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer changes expressions where one of the operands is a
*        number one. Examples are mentioned below.
*
* Optimizations are now only on these operators: *, /, ^.
*
* List of performed simplifications (by examples):
*
* @par Operator ^
* 1 ^ (EqOpExpr) or (EqOpExpr) ^ 1.
* @code
* return 1 ^ (a == b);
* @endcode
* can be optimized to
* @code
* return a != b;
* @endcode
* 1 ^ SomeCasts(EqOpExpr) or SomeCasts(EqOpExpr) ^ 1.
* @code
* return 1 ^ IntToPtrCastExpr<int>(a == b);
* @endcode
* can be optimized to
* @code
* return a != b;
* @endcode
*
* @par Operator *
* 1(ConstInt/ConstFloat) * anything (vica versa).
* @code
* return 1 * a;
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
*
* @par Operator /
* Anything / 1(ConstInt/ConstFloat).
* @code
* return a / 1;
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class OneSubOptimizer final: public SubOptimizer {
public:
	OneSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~OneSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<MulOpExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<BitXorOpExpr> expr) override;
	/// @}

	bool isConstFloatOne(ShPtr<Expression> expr) const;
	bool isConstIntOne(ShPtr<Expression> expr) const;
	bool isOne(ShPtr<ConstFloat> value) const;
	bool isOne(ShPtr<ConstInt> value) const;
	bool isOpOne(ShPtr<Expression> expr) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
