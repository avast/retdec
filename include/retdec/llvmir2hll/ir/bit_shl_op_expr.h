/**
* @file include/retdec/llvmir2hll/ir/bit_shl_op_expr.h
* @brief A bit left shift operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_BIT_SHL_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_BIT_SHL_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A bit left shift operator.
*
* This operator has the same meaning as the '<<' operator in C.
*
* Instances of this class have reference object semantics.
*/
class BitShlOpExpr: public BinaryOpExpr {
public:
	static ShPtr<BitShlOpExpr> create(ShPtr<Expression> op1,
		ShPtr<Expression> op2);

	virtual ~BitShlOpExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	BitShlOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
