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
	virtual Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	Expression* getFirstOperand() const;
	Expression* getSecondOperand() const;

	void setFirstOperand(Expression* first);
	void setSecondOperand(Expression* second);

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject,
		Value* arg = nullptr) override;
	/// @}

protected:
	BinaryOpExpr(Expression* op1, Expression* op2);

protected:
	/// First operand.
	Expression* op1 = nullptr;

	/// Second operand.
	Expression* op2 = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
