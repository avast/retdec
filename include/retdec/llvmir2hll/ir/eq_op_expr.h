/**
* @file include/retdec/llvmir2hll/ir/eq_op_expr.h
* @brief An equality operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_EQ_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_EQ_OP_EXPR_H

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief An equality operator.
*
* This operator has the same meaning as the '==' operator in C.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class EqOpExpr final: public BinaryOpExpr {
public:
	static EqOpExpr* create(Expression* op1,
		Expression* op2);

	virtual bool isEqualTo(Value* otherValue) const override;
	virtual Value* clone() override;
	virtual Type* getType() const override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

    static bool classof(const Value* v) {
        return v->getKind() == Value::ValueKind::EqOpExpr; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	EqOpExpr(Expression* op1, Expression* op2);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
