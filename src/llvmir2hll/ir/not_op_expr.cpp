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
NotOpExpr::NotOpExpr(Expression* op):
	UnaryOpExpr(op) {}

bool NotOpExpr::isEqualTo(Value* otherValue) const {
	if (NotOpExpr* otherValueNotOpExpr = cast<NotOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueNotOpExpr->getOperand());
	}
	return false;
}

Value* NotOpExpr::clone() {
	NotOpExpr* notOpExpr(NotOpExpr::create(ucast<Expression>(op->clone())));
	notOpExpr->setMetadata(getMetadata());
	return notOpExpr;
}

Type* NotOpExpr::getType() const {
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
NotOpExpr* NotOpExpr::create(Expression* op) {
	PRECONDITION_NON_NULL(op);

	NotOpExpr* expr(new NotOpExpr(op));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void NotOpExpr::accept(Visitor *v) {
	v->visit(ucast<NotOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
