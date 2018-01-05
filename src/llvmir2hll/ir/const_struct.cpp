/**
* @file src/llvmir2hll/ir/const_struct.cpp
* @brief Implementation of ConstStruct.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a struct constant initialized to the given value.
*
* See create() for more information.
*/
ConstStruct::ConstStruct(Type value, ShPtr<StructType> type):
	Constant(), value(value), type(type) {}

/**
* @brief Destructs the constant.
*/
ConstStruct::~ConstStruct() {}

ShPtr<Value> ConstStruct::clone() {
	// Clone all struct members.
	Type newValue;
	for (const auto &member : value) {
		newValue.push_back(Item(
			ucast<ConstInt>(member.first->clone()),
			ucast<Expression>(member.second->clone())));
	}

	ShPtr<ConstStruct> constStruct(ConstStruct::create(newValue, type));
	constStruct->setMetadata(getMetadata());
	return constStruct;
}

bool ConstStruct::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values have to be equal.
	if (ShPtr<ConstStruct> otherConstStruct = cast<ConstStruct>(otherValue)) {
		if (getType() != otherConstStruct->getType()) {
			return false;
		}
		return value == otherConstStruct->value;
	}
	return false;
}

ShPtr<Type> ConstStruct::getType() const {
	return type;
}

void ConstStruct::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// For each structure member...
	for (auto &member : value) {
		if (member.first == oldExpr && isa<ConstInt>(newExpr)) {
			member.first = cast<ConstInt>(newExpr);
		} else {
			member.first->replace(oldExpr, newExpr);
		}

		if (member.second == oldExpr) {
			member.second = newExpr;
		} else {
			member.second->replace(oldExpr, newExpr);
		}
	}
}

/**
* @brief Returns the constant's value.
*/
ConstStruct::Type ConstStruct::getValue() const {
	return value;
}

/**
* @brief Creates a struct constant initialized to the given value.
*
* @param[in] value Value of the constant.
* @param[in] type Type of the constant.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<ConstStruct> ConstStruct::create(Type value, ShPtr<StructType> type) {
	PRECONDITION_NON_NULL(type);

	ShPtr<ConstStruct> constStruct(new ConstStruct(value, type));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	for (const auto &member : value) {
		member.first->addObserver(constStruct);
		member.second->addObserver(constStruct);
	}

	return constStruct;
}

/**
* @brief Updates the structure according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* It replaces @a subject with @arg. For example, if @a subject is an
* expression in a field, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any expression in the structure's fields
*  - @a arg is not an expression
*
* @par Preconditions
*  - both @a subject and @a arg are non-null
*
* @see Subject::update()
*/
void ConstStruct::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newExpr = cast<Expression>(arg);
	if (!newExpr) {
		return;
	}

	for (auto &member : value) {
		if (member.second == subject) {
			member.second = newExpr;
		}
	}
}

void ConstStruct::accept(Visitor *v) {
	v->visit(ucast<ConstStruct>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
