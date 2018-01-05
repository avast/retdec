/**
* @file include/retdec/llvmir2hll/ir/fp_to_int_cast_expr.h
* @brief The casting of LLVM instructions FPtoSI/FPtoUI.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_FP_TO_INT_CAST_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_FP_TO_INT_CAST_EXPR_H

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief Cast of LLVM instructions FPtoSI/FPtoUI.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class FPToIntCastExpr final: public CastExpr {
public:
	static ShPtr<FPToIntCastExpr> create(ShPtr<Expression> op, ShPtr<Type> dstType);

	virtual ~FPToIntCastExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	FPToIntCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
