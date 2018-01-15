/**
* @file include/retdec/llvmir2hll/ir/array_index_op_expr.h
* @brief An array subscript operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_ARRAY_INDEX_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_ARRAY_INDEX_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief An array subscript operator.
*
* This operator has the same meaning as the '[]' operator in C.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ArrayIndexOpExpr final: public BinaryOpExpr {
public:
	static ShPtr<ArrayIndexOpExpr> create(ShPtr<Expression> base,
		ShPtr<Expression> index);

	virtual ~ArrayIndexOpExpr() override;

	virtual ShPtr<Type> getType() const override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	ShPtr<Expression> getBase() const;
	ShPtr<Expression> getIndex() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ArrayIndexOpExpr(ShPtr<Expression> base, ShPtr<Expression> index);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
