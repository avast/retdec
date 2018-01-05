/**
* @file include/retdec/llvmir2hll/ir/cast_expr.h
* @brief Base class for cast instructions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CAST_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_CAST_EXPR_H

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief Base class for cast instructions.
*
* Instances of this class have reference object semantics.
*/
class CastExpr: public Expression {
public:
	virtual ~CastExpr() override;

	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	void setOperand(ShPtr<Expression> newOp);
	ShPtr<Expression> getOperand() const;

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject,
		ShPtr<Value> arg = nullptr) override;
	/// @}

protected:
	CastExpr(ShPtr<Expression> op, ShPtr<Type> dstType);

protected:
	/// Operand.
	ShPtr<Expression> op;

	/// Destination type.
	ShPtr<Type> dstType;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
