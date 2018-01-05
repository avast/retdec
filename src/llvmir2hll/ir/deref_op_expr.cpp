/**
* @file src/llvmir2hll/ir/deref_op_expr.cpp
* @brief Implementation of DerefOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a dereference operator.
*
* See create() for more information.
*/
DerefOpExpr::DerefOpExpr(ShPtr<Expression> op):
	UnaryOpExpr(op) {}

/**
* @brief Destructs the operator.
*/
DerefOpExpr::~DerefOpExpr() {
	// Observers are removed in the superclass.
}

bool DerefOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<DerefOpExpr> otherValueDerefOpExpr = cast<DerefOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueDerefOpExpr->getOperand());
	}
	return false;
}

ShPtr<Value> DerefOpExpr::clone() {
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(cast<Expression>(
		op->clone())));
	derefOpExpr->setMetadata(getMetadata());
	return derefOpExpr;
}

/**
* @brief Creates a new dereference operator.
*
* @param[in] op Operand.
*
* @par Preconditions
*  - @a op is non-null
*/
ShPtr<DerefOpExpr> DerefOpExpr::create(ShPtr<Expression> op) {
	PRECONDITION_NON_NULL(op);

	ShPtr<DerefOpExpr> expr(new DerefOpExpr(op));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void DerefOpExpr::accept(Visitor *v) {
	v->visit(ucast<DerefOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
