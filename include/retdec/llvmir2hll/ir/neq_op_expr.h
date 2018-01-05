/**
* @file include/retdec/llvmir2hll/ir/neq_op_expr.h
* @brief A non-equality operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_NEQ_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_NEQ_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A non-equality operator.
*
* This operator has the same meaning as the '!=' operator in C.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class NeqOpExpr final: public BinaryOpExpr {
public:
	static ShPtr<NeqOpExpr> create(ShPtr<Expression> op1,
		ShPtr<Expression> op2);

	virtual ~NeqOpExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;
	virtual ShPtr<Type> getType() const override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	NeqOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
