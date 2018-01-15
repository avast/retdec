/**
* @file src/llvmir2hll/ir/cast_expr.cpp
* @brief Implementation of CastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator.
*/
CastExpr::CastExpr(ShPtr<Expression> op, ShPtr<Type> dstType):
	op(op), dstType(dstType) {
		PRECONDITION_NON_NULL(op);
		PRECONDITION_NON_NULL(dstType);
}

/**
* @brief Destructs the operator.
*/
CastExpr::~CastExpr() {}

ShPtr<Type> CastExpr::getType() const {
	return dstType;
}

void CastExpr::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	if (op == oldExpr) {
		setOperand(newExpr);
	} else if (op) {
		op->replace(oldExpr, newExpr);
	}
}

/**
* @brief Sets a new operand.
*
* @par Preconditions
*  - @a newOp is non-null
*/
void CastExpr::setOperand(ShPtr<Expression> newOp) {
	PRECONDITION_NON_NULL(newOp);

	op->removeObserver(shared_from_this());
	newOp->addObserver(shared_from_this());
	op = newOp;
}

/**
* @brief Returns the operand.
*/
ShPtr<Expression> CastExpr::getOperand() const {
	return op;
}

/**
* @brief Updates the cast according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is the operand of
* the cast, this function replaces it with @a arg.
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
void CastExpr::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	if (subject == op) {
		if (ShPtr<Expression> newOp = cast<Expression>(arg)) {
			setOperand(newOp);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
