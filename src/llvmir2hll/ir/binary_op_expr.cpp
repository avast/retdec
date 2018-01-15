/**
* @file src/llvmir2hll/ir/binary_op_expr.cpp
* @brief Implementation of BinaryOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a binary operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
BinaryOpExpr::BinaryOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
		op1(op1), op2(op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);
}

/**
* @brief Destructs the operator.
*/
BinaryOpExpr::~BinaryOpExpr() {}

ShPtr<Type> BinaryOpExpr::getType() const {
	ShPtr<Type> op1Type(op1->getType());
	ShPtr<Type> op2Type(op2->getType());

	// If both operands are of the same type, we can just return that type.
	if (op1Type == op2Type) {
		return op1Type;
	}

	// If the two operands are of type IntType but differ in signess, return an
	// unsigned integer.
	if (ShPtr<IntType> op1IntType = cast<IntType>(op1Type)) {
		if (ShPtr<IntType> op2IntType = cast<IntType>(op2Type)) {
			if (op1IntType->getSize() == op2IntType->getSize()) {
				return IntType::create(op1IntType->getSize(), false);
			}
		}
	}

	// If one of the operands is a pointer and the second is an integer, return
	// the type of the pointer. This way ensures a proper handling of pointer
	// arithmetic.
	if (isa<PointerType>(op1Type) && isa<IntType>(op2Type)) {
		return op1Type;
	} else if (isa<IntType>(op1Type) && isa<PointerType>(op2Type)) {
		return op2Type;
	}

	// Otherwise, the types are not compatible.
	return UnknownType::create();
}

void BinaryOpExpr::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	if (op1 == oldExpr) {
		setFirstOperand(newExpr);
	} else if (op1) {
		op1->replace(oldExpr, newExpr);
	}

	if (op2 == oldExpr) {
		setSecondOperand(newExpr);
	} else if (op2) {
		op2->replace(oldExpr, newExpr);
	}
}

/**
* @brief Returns the first operand.
*/
ShPtr<Expression> BinaryOpExpr::getFirstOperand() const {
	return op1;
}

/**
* @brief Returns the second operand.
*/
ShPtr<Expression> BinaryOpExpr::getSecondOperand() const {
	return op2;
}

/**
* @brief Sets the first operand.
*
* @par Preconditions
*  - @a first is non-null
*/
void BinaryOpExpr::setFirstOperand(ShPtr<Expression> first) {
	PRECONDITION_NON_NULL(first);

	op1->removeObserver(shared_from_this());
	first->addObserver(shared_from_this());
	op1 = first;
}

/**
* @brief Sets the second operand.
*
* @par Preconditions
*  - @a second is non-null
*/
void BinaryOpExpr::setSecondOperand(ShPtr<Expression> second) {
	PRECONDITION_NON_NULL(second);

	op2->removeObserver(shared_from_this());
	second->addObserver(shared_from_this());
	op2 = second;
}

/**
* @brief Updates the operator according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is the first
* operand of the operator, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any operand
*  - @a arg is not an expression
*
* @par Preconditions
*  - both operands are non-null
*
* @see Subject::update()
*/
void BinaryOpExpr::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newOperand = cast<Expression>(arg);
	if (!newOperand) {
		return;
	}

	if (subject == op1) {
		setFirstOperand(newOperand);
	} else if (subject == op2) {
		setSecondOperand(newOperand);
	}
}

} // namespace llvmir2hll
} // namespace retdec
