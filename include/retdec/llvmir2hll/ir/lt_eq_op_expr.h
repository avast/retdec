/**
* @file include/retdec/llvmir2hll/ir/lt_eq_op_expr.h
* @brief A less-than-or-equal operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_LT_EQ_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_LT_EQ_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A less-than-or-equal operator.
*
* This operator has the same meaning as the '<=' operator in C.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class LtEqOpExpr final: public BinaryOpExpr {
public:
	/// Variants of the operator.
	enum class Variant {
		UCmp, /// Unsigned compare.
		SCmp  /// Signed compare.
	};

	static ShPtr<LtEqOpExpr> create(ShPtr<Expression> op1,
		ShPtr<Expression> op2, Variant variant = Variant::UCmp);

	virtual ~LtEqOpExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;
	virtual ShPtr<Type> getType() const override;

	Variant getVariant() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Variant of the operation.
	Variant variant;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	LtEqOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2,
		Variant variant = Variant::UCmp);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
