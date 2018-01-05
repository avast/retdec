/**
* @file src/llvmir2hll/ir/int_to_fp_cast_expr.cpp
* @brief Implementation of IntToFPCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instructions SItoFP/UItoFP.
*
* See create() for more information.
*/
IntToFPCastExpr::IntToFPCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType,
		Variant variant):
	CastExpr(op, dstType), variant(variant) {}

/**
* @brief Destructs the operator.
*/
IntToFPCastExpr::~IntToFPCastExpr() {
	// Observers are removed in the superclass.
}

bool IntToFPCastExpr::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values of all operands have to be equal.
	if (ShPtr<IntToFPCastExpr> otherCastExpr = cast<IntToFPCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
ShPtr<Value> IntToFPCastExpr::clone() {
	ShPtr<IntToFPCastExpr> castExpr(IntToFPCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	castExpr->setMetadata(getMetadata());
	return castExpr;
}

/**
* @brief Returns variant of the integer to floating point cast.
*/
IntToFPCastExpr::Variant IntToFPCastExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new cast operator of LLVM instructions SItoFP/UItoFP.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
* @param[in] variant Variant of the cast.
*
* @par Preconditions
*  - @a op is non-null
*/
ShPtr<IntToFPCastExpr> IntToFPCastExpr::create(ShPtr<Expression> op,
		ShPtr<Type> dstType, Variant variant) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	ShPtr<IntToFPCastExpr> expr(new IntToFPCastExpr(op, dstType, variant));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void IntToFPCastExpr::accept(Visitor *v) {
	v->visit(ucast<IntToFPCastExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
