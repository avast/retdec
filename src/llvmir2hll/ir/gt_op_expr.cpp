/**
* @file src/llvmir2hll/ir/gt_op_expr.cpp
* @brief Implementation of GtOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a greater-than operator.
*
* See create() for more information.
*/
GtOpExpr::GtOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2,
		Variant variant):
	BinaryOpExpr(op1, op2), variant(variant) {}

/**
* @brief Destructs the operator.
*/
GtOpExpr::~GtOpExpr() {
	// Observers are removed in the superclass.
}

bool GtOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<GtOpExpr> otherValueGtOpExpr = cast<GtOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueGtOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueGtOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> GtOpExpr::clone() {
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(
		ucast<Expression>(op1->clone()),
		ucast<Expression>(op2->clone())));
	gtOpExpr->setMetadata(getMetadata());
	return gtOpExpr;
}

ShPtr<Type> GtOpExpr::getType() const {
	// The type of `x > y` should be bool.
	return IntType::create(1);
}

/**
* @brief Returns variant of operation.
*/
GtOpExpr::Variant GtOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new greater-than operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operator.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<GtOpExpr> GtOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<GtOpExpr> expr(new GtOpExpr(op1, op2, variant));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void GtOpExpr::accept(Visitor *v) {
	v->visit(ucast<GtOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
