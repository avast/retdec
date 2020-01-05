/**
* @file include/retdec/llvmir2hll/ir/ternary_op_expr.h
* @brief A ternary operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_TERNARY_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_TERNARY_OP_EXPR_H

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A ternary operator.
*
* This operator has the same behavior as the C ternary operator "?:".
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class TernaryOpExpr final: public Expression {
public:
	static TernaryOpExpr* create(Expression* cond,
		Expression* trueValue, Expression* falseValue);

	virtual Value* clone() override;

	virtual bool isEqualTo(Value* otherValue) const override;
	virtual Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	Expression* getCondition() const;
	Expression* getTrueValue() const;
	Expression* getFalseValue() const;

	void setCondition(Expression* newCond);
	void setTrueValue(Expression* newTrueValue);
	void setFalseValue(Expression* newFalseValue);

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject,
		Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

    static bool classof(const Value* v) {
        return v->getKind() == Value::ValueKind::TernaryOpExpr; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	TernaryOpExpr(Expression* cond, Expression* trueValue,
			Expression* falseValue);
private:
	/// Condition.
	Expression* cond = nullptr;

	/// True value.
	Expression* trueValue = nullptr;

	/// False value.
	Expression* falseValue = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
