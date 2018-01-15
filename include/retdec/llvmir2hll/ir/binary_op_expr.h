/**
* @file include/retdec/llvmir2hll/ir/binary_op_expr.h
* @brief A base class for all binary operators.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_BINARY_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_BINARY_OP_EXPR_H

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class for all binary operators.
*
* Instances of this class have reference object semantics.
*/
class BinaryOpExpr: public Expression {
public:
	virtual ~BinaryOpExpr() = 0;

	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	ShPtr<Expression> getFirstOperand() const;
	ShPtr<Expression> getSecondOperand() const;

	void setFirstOperand(ShPtr<Expression> first);
	void setSecondOperand(ShPtr<Expression> second);

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject,
		ShPtr<Value> arg = nullptr) override;
	/// @}

protected:
	BinaryOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2);

protected:
	/// First operand.
	ShPtr<Expression> op1;

	/// Second operand.
	ShPtr<Expression> op2;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
