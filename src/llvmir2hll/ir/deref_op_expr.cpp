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
DerefOpExpr::DerefOpExpr(Expression* op):
	UnaryOpExpr(op) {}

bool DerefOpExpr::isEqualTo(Value* otherValue) const {
	if (DerefOpExpr* otherValueDerefOpExpr = cast<DerefOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueDerefOpExpr->getOperand());
	}
	return false;
}

Value* DerefOpExpr::clone() {
	DerefOpExpr* derefOpExpr(DerefOpExpr::create(cast<Expression>(
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
DerefOpExpr* DerefOpExpr::create(Expression* op) {
	PRECONDITION_NON_NULL(op);

	DerefOpExpr* expr(new DerefOpExpr(op));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void DerefOpExpr::accept(Visitor *v) {
	v->visit(ucast<DerefOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
