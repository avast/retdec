/**
* @file src/llvmir2hll/ir/array_index_op_expr.cpp
* @brief Implementation of ArrayIndexOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an array subscript operator.
*
* See create() for more information.
*/
ArrayIndexOpExpr::ArrayIndexOpExpr(ShPtr<Expression> base, ShPtr<Expression> index):
	BinaryOpExpr(base, index) {}

/**
* @brief Destructs the operator.
*/
ArrayIndexOpExpr::~ArrayIndexOpExpr() {
	// Observers are removed in the superclass.
}

ShPtr<Type> ArrayIndexOpExpr::getType() const {
	ShPtr<Type> op1Type(op1->getType());

	if (ShPtr<ArrayType> op1ArrayType = cast<ArrayType>(op1Type)) {
		return op1ArrayType->getContainedType();
	}

	if (ShPtr<PointerType> op1PointerType = cast<PointerType>(op1Type)) {
		return op1PointerType->getContainedType();
	}

	// The type cannot be computed.
	return UnknownType::create();
}

bool ArrayIndexOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<ArrayIndexOpExpr> otherValueArrayIndexOpExpr =
			cast<ArrayIndexOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueArrayIndexOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueArrayIndexOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> ArrayIndexOpExpr::clone() {
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(ArrayIndexOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	arrayIndexOpExpr->setMetadata(getMetadata());
	return arrayIndexOpExpr;
}

/**
* @brief Returns the base (i.e. the first operand).
*/
ShPtr<Expression> ArrayIndexOpExpr::getBase() const {
	return getFirstOperand();
}

/**
* @brief Returns the index (i.e. the second operand).
*/
ShPtr<Expression> ArrayIndexOpExpr::getIndex() const {
	return getSecondOperand();
}

/**
* @brief Creates a new array subscript operator.
*
* @param[in] base Base part of the operator (op1).
* @param[in] index Index part of the operator (op2).
*
* An equivalent in C is @c base[index].
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<ArrayIndexOpExpr> ArrayIndexOpExpr::create(ShPtr<Expression> base,
		ShPtr<Expression> index) {
	PRECONDITION_NON_NULL(base);
	PRECONDITION_NON_NULL(index);

	ShPtr<ArrayIndexOpExpr> expr(new ArrayIndexOpExpr(base, index));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	base->addObserver(expr);
	index->addObserver(expr);

	return expr;
}

void ArrayIndexOpExpr::accept(Visitor *v) {
	v->visit(ucast<ArrayIndexOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
