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
UnaryOpExpr::UnaryOpExpr(Value::ValueKind k, Expression* op):
		Expression(k), op(op) {
	PRECONDITION_NON_NULL(op);
}

Type* UnaryOpExpr::getType() const {
	return op->getType();
}

void UnaryOpExpr::replace(Expression* oldExpr, Expression* newExpr) {
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
Expression* UnaryOpExpr::getOperand() const {
	return op;
}

/**
* @brief Sets a new operand.
*
* @par Preconditions
*  - @a operand is non-null
*/
void UnaryOpExpr::setOperand(Expression* newOp) {
	PRECONDITION_NON_NULL(newOp);

	op->removeObserver(this);
	newOp->addObserver(this);
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
void UnaryOpExpr::update(Value* subject, Value* arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	Expression* newOperand = cast<Expression>(arg);
	if (subject == op && newOperand) {
		setOperand(newOperand);
	}
}

} // namespace llvmir2hll
} // namespace retdec
