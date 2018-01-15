/**
* @file include/retdec/llvmir2hll/ir/struct_index_op_expr.h
* @brief A struct index operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_STRUCT_INDEX_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_STRUCT_INDEX_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ConstInt;
class Expression;
class Visitor;

/**
* @brief A struct index operator.
*
* This operator has the same meaning as the '.' operator in C. However, instead
* of field names, it uses numbers.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class StructIndexOpExpr final: public BinaryOpExpr {
public:
	static ShPtr<StructIndexOpExpr> create(ShPtr<Expression> base,
		ShPtr<ConstInt> fieldNumber);

	virtual ~StructIndexOpExpr() override;

	virtual ShPtr<Type> getType() const override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	StructIndexOpExpr(ShPtr<Expression> base, ShPtr<ConstInt> fieldNumber);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
