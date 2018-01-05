/**
* @file include/retdec/llvmir2hll/ir/bit_or_op_expr.h
* @brief A bit-or operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_BIT_OR_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_BIT_OR_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A bit-or operator.
*
* This operator has the same meaning as the '|' operator in C.
*
* Instances of this class have reference object semantics.
*/
class BitOrOpExpr: public BinaryOpExpr {
public:
	static ShPtr<BitOrOpExpr> create(ShPtr<Expression> op1,
		ShPtr<Expression> op2);

	virtual ~BitOrOpExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	BitOrOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
