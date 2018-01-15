/**
* @file src/llvmir2hll/ir/not_op_expr.cpp
* @brief Implementation of NotOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a logical negation operator.
*
* See create() for more information.
*/
NotOpExpr::NotOpExpr(ShPtr<Expression> op):
	UnaryOpExpr(op) {}

/**
* @brief Destructs the operator.
*/
NotOpExpr::~NotOpExpr() {
	// Observers are removed in the superclass.
}

bool NotOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<NotOpExpr> otherValueNotOpExpr = cast<NotOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueNotOpExpr->getOperand());
	}
	return false;
}

ShPtr<Value> NotOpExpr::clone() {
	ShPtr<NotOpExpr> notOpExpr(NotOpExpr::create(ucast<Expression>(op->clone())));
	notOpExpr->setMetadata(getMetadata());
	return notOpExpr;
}

ShPtr<Type> NotOpExpr::getType() const {
	// The type of `!x` should be bool.
	return IntType::create(1);
}

/**
* @brief Creates a new logical negation operator.
*
* @param[in] op Operand.
*
* @par Preconditions
*  - @a op is non-null
*/
ShPtr<NotOpExpr> NotOpExpr::create(ShPtr<Expression> op) {
	PRECONDITION_NON_NULL(op);

	ShPtr<NotOpExpr> expr(new NotOpExpr(op));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void NotOpExpr::accept(Visitor *v) {
	v->visit(ucast<NotOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
