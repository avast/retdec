/**
* @file include/retdec/llvmir2hll/ir/ext_cast_expr.h
* @brief The casting of LLVM instructions: FPExt, SExt, ZExt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_EXT_CAST_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_EXT_CAST_EXPR_H

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief Cast of LLVM Ext instructions.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ExtCastExpr final: public CastExpr {
public:
	/// Variants of the cast.
	enum class Variant {
		ZExt, /// Zero extension.
		SExt, /// Sign extension.
		FPExt /// Floating-point extension.
	};

	static ShPtr<ExtCastExpr> create(ShPtr<Expression> op, ShPtr<Type> dstType,
		Variant variant = Variant::ZExt);

	virtual ~ExtCastExpr() override;

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
	ExtCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType,
		Variant variant = Variant::ZExt);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
