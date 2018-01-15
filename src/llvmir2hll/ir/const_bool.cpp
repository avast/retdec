/**
* @file src/llvmir2hll/ir/const_bool.cpp
* @brief Implementation of ConstBool.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a bool constant initialized to the given value.
*
* See create() for more information.
*/
ConstBool::ConstBool(Type value):
	Constant(), value(value), type(IntType::create(1, false)) {}

/**
* @brief Destructs the constant.
*/
ConstBool::~ConstBool() {}

ShPtr<Value> ConstBool::clone() {
	ShPtr<ConstBool> constBool(ConstBool::create(value));
	constBool->setMetadata(getMetadata());
	return constBool;
}

bool ConstBool::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values have to be equal.
	if (ShPtr<ConstBool> otherConstBool = cast<ConstBool>(otherValue)) {
		return value == otherConstBool->value;
	}
	return false;
}

ShPtr<Type> ConstBool::getType() const {
	return type;
}

void ConstBool::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Returns the constant's value.
*/
ConstBool::Type ConstBool::getValue() const {
	return value;
}

/**
* @brief Determines if the value of the constant is @c true.
*
* @return @c true if the constant is @c true, @c false otherwise.
*/
bool ConstBool::isTrue() const {
	return value;
}

/**
* @brief Determines if the value of the constant is @c false.
*
* @return @c true if the constant is @c false, @c false otherwise.
*/
bool ConstBool::isFalse() const {
	return !value;
}

/**
* @brief Constructs a bool constant initialized to the given value.
*
* @param[in] value Value of the constant.
*
* If @a value is not given, the constant is initialized to the default bool
* value.
*/
ShPtr<ConstBool> ConstBool::create(Type value) {
	return ShPtr<ConstBool>(new ConstBool(value));
}

void ConstBool::accept(Visitor *v) {
	v->visit(ucast<ConstBool>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
