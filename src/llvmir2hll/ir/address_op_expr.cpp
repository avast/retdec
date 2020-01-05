/**
* @file src/llvmir2hll/ir/address_op_expr.cpp
* @brief Implementation of AddressOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an address operator.
*
* See create() for more information.
*/
AddressOpExpr::AddressOpExpr(Expression* op):
	UnaryOpExpr(op) {}

bool AddressOpExpr::isEqualTo(Value* otherValue) const {
	if (AddressOpExpr* otherValueAddressOpExpr = cast<AddressOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueAddressOpExpr->getOperand());
	}
	return false;
}

Value* AddressOpExpr::clone() {
	AddressOpExpr* addressOpExpr(AddressOpExpr::create(
		ucast<Expression>(op->clone())));
	addressOpExpr->setMetadata(getMetadata());
	return addressOpExpr;
}

void AddressOpExpr::accept(Visitor *v) {
	v->visit(ucast<AddressOpExpr>(this));
}

/**
* @brief Creates a new address operator.
*
* @param[in] op Operand.
*
* @par Preconditions
*  - @a op is non-null
*/
AddressOpExpr* AddressOpExpr::create(Expression* op) {
	PRECONDITION_NON_NULL(op);

	AddressOpExpr* expr(new AddressOpExpr(op));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

} // namespace llvmir2hll
} // namespace retdec
