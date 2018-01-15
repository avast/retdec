/**
* @file include/retdec/llvmir2hll/ir/address_op_expr.h
* @brief An address operator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_ADDRESS_OP_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_ADDRESS_OP_EXPR_H

#include "retdec/llvmir2hll/ir/unary_op_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief An address operator.
*
* This operator has the same meaning as the '&' operator in C.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class AddressOpExpr final: public UnaryOpExpr {
public:
	static ShPtr<AddressOpExpr> create(ShPtr<Expression> op);

	virtual ~AddressOpExpr() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Value> clone() override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit AddressOpExpr(ShPtr<Expression> op);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
