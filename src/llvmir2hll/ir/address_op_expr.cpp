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
AddressOpExpr::AddressOpExpr(ShPtr<Expression> op):
	UnaryOpExpr(op) {}

/**
* @brief Destructs the operator.
*/
AddressOpExpr::~AddressOpExpr() {
	// Observers are removed in the superclass.
}

bool AddressOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<AddressOpExpr> otherValueAddressOpExpr = cast<AddressOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueAddressOpExpr->getOperand());
	}
	return false;
}

ShPtr<Value> AddressOpExpr::clone() {
	ShPtr<AddressOpExpr> addressOpExpr(AddressOpExpr::create(
		ucast<Expression>(op->clone())));
	addressOpExpr->setMetadata(getMetadata());
	return addressOpExpr;
}

void AddressOpExpr::accept(Visitor *v) {
	v->visit(ucast<AddressOpExpr>(shared_from_this()));
}

/**
* @brief Creates a new address operator.
*
* @param[in] op Operand.
*
* @par Preconditions
*  - @a op is non-null
*/
ShPtr<AddressOpExpr> AddressOpExpr::create(ShPtr<Expression> op) {
	PRECONDITION_NON_NULL(op);

	ShPtr<AddressOpExpr> expr(new AddressOpExpr(op));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

} // namespace llvmir2hll
} // namespace retdec
