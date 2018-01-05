/**
* @file include/retdec/llvmir2hll/ir/int_to_fp_cast_expr.h
* @brief The casting of LLVM instructions SItoFP/UItoFP.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_INT_TO_FP_CAST_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_INT_TO_FP_CAST_EXPR_H

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief Cast of LLVM instruction SItoFP/UItoFP.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class IntToFPCastExpr final: public CastExpr {
public:
	/// Variants of the integer to floating point casts
	enum class Variant {
		SIToFP, /// Signed integer to floating-point.
		UIToFP  /// Unsigned integer to floating-point.
	};

	static ShPtr<IntToFPCastExpr> create(ShPtr<Expression> op, ShPtr<Type> dstType,
		Variant variant = Variant::UIToFP);

	virtual ~IntToFPCastExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	Variant getVariant() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Variant of the cast.
	Variant variant;
private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	IntToFPCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType,
		Variant variant = Variant::UIToFP);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
