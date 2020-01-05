/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/const_operator_const_sub_optimizer.h
* @brief A sub-optimization class that optimize expression like Constant operator
*        constant
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_CONST_OPERATOR_CONST_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_CONST_OPERATOR_CONST_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer optimizes expressions where the first and the second
*        operand is a constant. Examples are mentioned below.
*
* Optimizations are now only on these operators: +, -, *, /, &, |, ^.
*
* List of performed simplifications (by examples):
*
* @par Operator +
* (ConstInt/ConstFloat) + (ConstInt/ConstFloat).
* @code
* return 2 + 5;
* @endcode
* can be optimized to
* @code
* return 7;
* @endcode
*
* @par Operator &
* ConstInt & ConstInt.
* @code
* return 10 & 22;
* @endcode
* can be optimized to
* @code
* return 2;
* @endcode
*
* @par Operator |
* ConstInt | ConstInt.
* @code
* return 10 | 22;
* @endcode
* can be optimized to
* @code
* return 30;
* @endcode
*
* @par Operator ^
* ConstInt ^ ConstInt.
* @code
* return 10 ^ 22;
* @endcode
* can be optimized to
* @code
* return 28;
* @endcode
*
* @par Operator -
* (ConstInt/ConstFloat) - (ConstInt/ConstFloat).
* @code
* return 2 - 5;
* @endcode
* can be optimized to
* @code
* return -3;
* @endcode
*
* @par Operator *
* (ConstInt/ConstFloat) * (ConstInt/ConstFloat).
* @code
* return 2 * 5;
* @endcode
* can be optimized to
* @code
* return 10;
* @endcode
*
* @par Operator /
* (ConstInt/ConstFloat) / (ConstInt/ConstFloat).
* @code
* return 10 / 5;
* @endcode
* can be optimized to
* @code
* return 2;
* @endcode
*
* @par Operator <, >, <=, >=, ==, !, &&, ||
* (ConstInt/ConstFloat/ConstBool) op (ConstInt/ConstFloat/ConstBool).
* @code
* return 2 == 5;
* @endcode
* can be optimized to
* @code
* return false;
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class ConstOperatorConstSubOptimizer final: public SubOptimizer {
public:
	ConstOperatorConstSubOptimizer(
		ArithmExprEvaluator* arithmExprEvaluator);

	static SubOptimizer* create(ArithmExprEvaluator*
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(AddOpExpr* expr) override;
	virtual void visit(SubOpExpr* expr) override;
	virtual void visit(MulOpExpr* expr) override;
	virtual void visit(DivOpExpr* expr) override;
	virtual void visit(BitAndOpExpr* expr) override;
	virtual void visit(BitOrOpExpr* expr) override;
	virtual void visit(BitXorOpExpr* expr) override;
	virtual void visit(LtOpExpr* expr) override;
	virtual void visit(LtEqOpExpr* expr) override;
	virtual void visit(GtOpExpr* expr) override;
	virtual void visit(GtEqOpExpr* expr) override;
	virtual void visit(EqOpExpr* expr) override;
	virtual void visit(NeqOpExpr* expr) override;
	virtual void visit(AndOpExpr* expr) override;
	virtual void visit(OrOpExpr* expr) override;
	/// @}

	void tryOptimizeConstConstOperand(BinaryOpExpr* expr);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
