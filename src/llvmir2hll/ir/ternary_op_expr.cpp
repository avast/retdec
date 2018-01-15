/**
* @file src/llvmir2hll/ir/ternary_op_expr.cpp
* @brief Implementation of TernaryOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a ternary operator.
*
* See create() for more information.
*/
TernaryOpExpr::TernaryOpExpr(ShPtr<Expression> cond, ShPtr<Expression> trueValue,
	ShPtr<Expression> falseValue):
		Expression(), cond(cond), trueValue(trueValue), falseValue(falseValue) {}

/**
* @brief Destructs the operator.
*/
TernaryOpExpr::~TernaryOpExpr() {}

ShPtr<Value> TernaryOpExpr::clone() {
	ShPtr<TernaryOpExpr> ternaryOpExpr(TernaryOpExpr::create(
		ucast<Expression>(cond->clone()),
		ucast<Expression>(trueValue->clone()),
		ucast<Expression>(falseValue->clone())));
	ternaryOpExpr->setMetadata(getMetadata());
	return ternaryOpExpr;
}

bool TernaryOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types, conditions, true and false values have to be equal.
	if (ShPtr<TernaryOpExpr> otherTernaryOpExpr = cast<TernaryOpExpr>(otherValue)) {
		return cond->isEqualTo(otherTernaryOpExpr->cond) &&
			trueValue->isEqualTo(otherTernaryOpExpr->trueValue) &&
			falseValue->isEqualTo(otherTernaryOpExpr->falseValue);
	}
	return false;
}

ShPtr<Type> TernaryOpExpr::getType() const {
	// Both true and false value must have the same types.
	if (trueValue->getType() == falseValue->getType()) {
		return trueValue->getType();
	}
	return UnknownType::create();
}

void TernaryOpExpr::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	if (cond == oldExpr) {
		setCondition(newExpr);
	} else {
		cond->replace(oldExpr, newExpr);
	}

	if (trueValue == oldExpr) {
		setTrueValue(newExpr);
	} else {
		trueValue->replace(oldExpr, newExpr);
	}

	if (falseValue == oldExpr) {
		setFalseValue(newExpr);
	} else {
		falseValue->replace(oldExpr, newExpr);
	}
}

/**
* @brief Returns the operator condition.
*/
ShPtr<Expression> TernaryOpExpr::getCondition() const {
	return cond;
}

/**
* @brief Returns the true value.
*/
ShPtr<Expression> TernaryOpExpr::getTrueValue() const {
	return trueValue;
}

/**
* @brief Returns the false value.
*/
ShPtr<Expression> TernaryOpExpr::getFalseValue() const {
	return falseValue;
}

/**
* @brief Sets the condition.
*
* @par Preconditions
*  - @a newCond is non-null
*/
void TernaryOpExpr::setCondition(ShPtr<Expression> newCond) {
	PRECONDITION_NON_NULL(newCond);

	cond->removeObserver(shared_from_this());
	newCond->addObserver(shared_from_this());
	cond = newCond;
}

/**
* @brief Sets the true value.
*
* @par Preconditions
*  - @a newTrueValue is non-null
*/
void TernaryOpExpr::setTrueValue(ShPtr<Expression> newTrueValue) {
	PRECONDITION_NON_NULL(newTrueValue);

	trueValue->removeObserver(shared_from_this());
	newTrueValue->addObserver(shared_from_this());
	trueValue = newTrueValue;
}

/**
* @brief Sets the false value.
*
* @par Preconditions
*  - @a newFalseValue is non-null
*/
void TernaryOpExpr::setFalseValue(ShPtr<Expression> newFalseValue) {
	PRECONDITION_NON_NULL(newFalseValue);

	falseValue->removeObserver(shared_from_this());
	newFalseValue->addObserver(shared_from_this());
	falseValue = newFalseValue;
}

/**
* @brief Creates a new ternary operator.
*
* @param[in] cond Condition.
* @param[in] trueValue True value.
* @param[in] falseValue False value.
*
* The C equivalent of this operator is <tt>cond ? trueValue : falseValue</tt>.
*
* @par Preconditions
*  - all arguments are non-null
*/
ShPtr<TernaryOpExpr> TernaryOpExpr::create(ShPtr<Expression> cond,
		ShPtr<Expression> trueValue, ShPtr<Expression> falseValue) {
	PRECONDITION_NON_NULL(cond);
	PRECONDITION_NON_NULL(trueValue);
	PRECONDITION_NON_NULL(falseValue);

	ShPtr<TernaryOpExpr> expr(new TernaryOpExpr(cond, trueValue, falseValue));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	cond->addObserver(expr);
	trueValue->addObserver(expr);
	falseValue->addObserver(expr);

	return expr;
}

/**
* @brief Updates the operator according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @arg. For example, if @a subject is the condition of
* the operator, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any operand
*  - @a arg is not an expression
*
* @par Preconditions
*  - both arguments are non-null
*
* @see Subject::update()
*/
void TernaryOpExpr::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newOperand = cast<Expression>(arg);
	if (!newOperand) {
		return;
	}

	if (subject == cond) {
		setCondition(newOperand);
	} else if (subject == trueValue) {
		setTrueValue(newOperand);
	} else if (subject == falseValue) {
		setFalseValue(newOperand);
	}
}

void TernaryOpExpr::accept(Visitor *v) {
	v->visit(ucast<TernaryOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
