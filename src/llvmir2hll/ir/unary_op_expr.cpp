/**
* @file src/llvmir2hll/ir/unary_op_expr.cpp
* @brief Implementation of UnaryOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/unary_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a unary operator.
*
* @param[in] op Operand.
*
* @par Preconditions
*  - @a op is non-null
*/
UnaryOpExpr::UnaryOpExpr(ShPtr<Expression> op):
		op(op) {
	PRECONDITION_NON_NULL(op);
}

/**
* @brief Destructs the operator.
*/
UnaryOpExpr::~UnaryOpExpr() {}

ShPtr<Type> UnaryOpExpr::getType() const {
	return op->getType();
}

void UnaryOpExpr::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	if (op == oldExpr) {
		setOperand(newExpr);
	} else if (op) {
		op->replace(oldExpr, newExpr);
	}
}

/**
* @brief Returns the operand.
*/
ShPtr<Expression> UnaryOpExpr::getOperand() const {
	return op;
}

/**
* @brief Sets a new operand.
*
* @par Preconditions
*  - @a operand is non-null
*/
void UnaryOpExpr::setOperand(ShPtr<Expression> newOp) {
	PRECONDITION_NON_NULL(newOp);

	op->removeObserver(shared_from_this());
	newOp->addObserver(shared_from_this());
	op = newOp;
}

/**
* @brief Updates the operator according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @arg. For example, if @a subject is the operand of
* the operator, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to the operand
*  - @a arg is not an expression
*
* @par Preconditions
*  - both operands are non-null
*
* @see Subject::update()
*/
void UnaryOpExpr::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newOperand = cast<Expression>(arg);
	if (subject == op && newOperand) {
		setOperand(newOperand);
	}
}

} // namespace llvmir2hll
} // namespace retdec
