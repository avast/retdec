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
	static ShPtr<TernaryOpExpr> create(ShPtr<Expression> cond,
		ShPtr<Expression> trueValue, ShPtr<Expression> falseValue);

	virtual ~TernaryOpExpr() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	ShPtr<Expression> getCondition() const;
	ShPtr<Expression> getTrueValue() const;
	ShPtr<Expression> getFalseValue() const;

	void setCondition(ShPtr<Expression> newCond);
	void setTrueValue(ShPtr<Expression> newTrueValue);
	void setFalseValue(ShPtr<Expression> newFalseValue);

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject,
		ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	TernaryOpExpr(ShPtr<Expression> cond, ShPtr<Expression> trueValue,
			ShPtr<Expression> falseValue);
private:
	/// Condition.
	ShPtr<Expression> cond;

	/// True value.
	ShPtr<Expression> trueValue;

	/// False value.
	ShPtr<Expression> falseValue;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
