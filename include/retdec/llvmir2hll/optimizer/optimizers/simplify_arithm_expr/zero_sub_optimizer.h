/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/zero_sub_optimizer.h
* @brief A sub-optimization class that optimize expression with zero operand.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_ZERO_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_ZERO_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer changes expressions where one of the operands is a
*        zero. Examples are mentioned below.
*
* Optimizations are now only on these operators: +, -, *, /, %, &, |, ^.
*
* List of performed simplifications (by examples):
*
* @par Operator +
* 0(ConstInt/ConstFloat) + anything (vica versa).
* @code
* return 0 + a;
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
*
* @par Operator &
* 0(ConstInt) & anything (vica versa).
* @code
* return 0 & a;
* @endcode
* can be optimized to
* @code
* return 0;
* @endcode
*
* @par Operator |
* 0(ConstInt) | anything (vica versa).
* @code
* return 0 | a;
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
*
* @par Operator ^
* 0(ConstInt) ^ anything (vica versa).
* @code
* return 0 ^ a;
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
*
* @par Operator -
* 0(ConstInt/ConstFloat) - (ConstInt/ConstFloat).
* @code
* return 0 - 2;
* @endcode
* can be optimized to
* @code
* return -2;
* @endcode
* 0(ConstInt/ConstFloat) - (NegOpExpr).
* @code
* return 0 - a(NegOpExpr);
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
* 0(ConstInt/ConstFloat) - anything(Not NegOpExpr).
* @code
* return 0 - a(Not NegOpExpr);
* @endcode
* can be optimized to
* @code
* return a(NegOpExpr);
* @endcode
* Anything - 0(ConstInt/ConstFloat).
* @code
* return a - 0;
* @endcode
* can be optimized to
* @code
* return a;
* @endcode
*
* @par Operator *
* 0(ConstInt/ConstFloat) * anything (vica versa).
* @code
* return 0 * a;
* @endcode
* can be optimized to
* @code
* return 0;
* @endcode
*
* @par Operator /
* 0(ConstInt/ConstFloat) / anything.
* @code
* return 0 / a;
* @endcode
* can be optimized to
* @code
* return 0;
* @endcode
*
* @par Operator %
* 0(ConstInt/ConstFloat) % anything.
* @code
* return 0 % a;
* @endcode
* can be optimized to
* @code
* return 0;
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class ZeroSubOptimizer final: public SubOptimizer {
public:
	ZeroSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~ZeroSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	virtual void visit(ShPtr<MulOpExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<ModOpExpr> expr) override;
	virtual void visit(ShPtr<BitAndOpExpr> expr) override;
	virtual void visit(ShPtr<BitOrOpExpr> expr) override;
	virtual void visit(ShPtr<BitXorOpExpr> expr) override;
	/// @}

	bool isConstFloatZero(ShPtr<Expression> expr) const;
	bool isConstIntZero(ShPtr<Expression> expr) const;
	bool isOpZero(ShPtr<Expression> expr) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
