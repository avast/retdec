/**
* @file include/retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h
* @brief The casting of LLVM instruction IntToPtr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_INT_TO_PTR_CAST_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_INT_TO_PTR_CAST_EXPR_H

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief Cast of LLVM instruction IntToPtr.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class IntToPtrCastExpr final: public CastExpr {
public:
	static ShPtr<IntToPtrCastExpr> create(ShPtr<Expression> op, ShPtr<Type> dstType);

	virtual ~IntToPtrCastExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	IntToPtrCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
