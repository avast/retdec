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
	virtual Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	Expression* getOperand() const;

	void setOperand(Expression* newOp);

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject,
		Value* arg = nullptr) override;
	/// @}

	static bool classof(const Value* v) {
		return v->getKind() >= Value::ValueKind::UnaryOpExpr
				&& v->getKind() <= Value::ValueKind::_UnaryOpExpr_END; }

protected:
	explicit UnaryOpExpr(Value::ValueKind k, Expression* op);

protected:
	/// Operand.
	Expression* op = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
