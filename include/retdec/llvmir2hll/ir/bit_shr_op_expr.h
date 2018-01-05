/**
* @file include/retdec/llvmir2hll/ir/bit_shr_op_expr.h
* @brief A bit right shift operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_BIT_SHR_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_BIT_SHR_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A bit right shift operator.
*
* This operator has the same meaning as the '>>' operator in C. However, it
* contains an additional flag that determines whether the shift is arithmetical
* or logical. Recall that in C, this is implementation defined.
*
* Instances of this class have reference object semantics.
*/
class BitShrOpExpr: public BinaryOpExpr {
public:
	/// Variants of the operator.
	enum class Variant {
		Arithmetical, ///< Arithmetical shift.
		Logical       ///< Logical shift.
	};

public:
	static ShPtr<BitShrOpExpr> create(ShPtr<Expression> op1,
		ShPtr<Expression> op2, Variant variant = Variant::Arithmetical);

	virtual ~BitShrOpExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	Variant getVariant() const;
	bool isLogical() const;
	bool isArithmetical() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	BitShrOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2,
		Variant variant = Variant::Arithmetical);

	/// Variant of the operator.
	Variant variant;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
