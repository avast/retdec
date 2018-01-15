/**
* @file include/retdec/llvmir2hll/ir/unary_op_expr.h
* @brief A base class for all unary operators.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_UNARY_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_UNARY_OP_EXPR_H

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class for all unary operators.
*
* Instances of this class have reference object semantics.
*/
class UnaryOpExpr: public Expression {
public:
	virtual ~UnaryOpExpr() override = 0;

	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	ShPtr<Expression> getOperand() const;

	void setOperand(ShPtr<Expression> newOp);

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject,
		ShPtr<Value> arg = nullptr) override;
	/// @}

protected:
	explicit UnaryOpExpr(ShPtr<Expression> op);

protected:
	/// Operand.
	ShPtr<Expression> op;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
