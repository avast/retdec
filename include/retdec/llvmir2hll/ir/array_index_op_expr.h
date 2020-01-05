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
	static ArrayIndexOpExpr* create(Expression* base,
		Expression* index);

	virtual Type* getType() const override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual Value* clone() override;

	Expression* getBase() const;
	Expression* getIndex() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

	static bool classof(const Value* v) {
		return v->getKind() == Value::ValueKind::ArrayIndexOpExpr; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ArrayIndexOpExpr(Expression* base, Expression* index);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
