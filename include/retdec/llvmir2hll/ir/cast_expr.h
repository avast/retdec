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
	virtual Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	void setOperand(Expression* newOp);
	Expression* getOperand() const;

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject,
		Value* arg = nullptr) override;
	/// @}

	static bool classof(const Value* v) {
		return v->getKind() >= Value::ValueKind::CastExpr
				&& v->getKind() <= Value::ValueKind::_CastExpr_END; }

protected:
	CastExpr(Value::ValueKind k, Expression* op, Type* dstType);

protected:
	/// Operand.
	Expression* op = nullptr;

	/// Destination type.
	Type* dstType = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
