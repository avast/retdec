/**
* @file src/llvmir2hll/ir/const_array.cpp
* @brief Implementation of ConstArray.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an array constant.
*
* See create() or createUninitialized() for more information.
*/
ConstArray::ConstArray(ArrayValue value, ShPtr<ArrayType> type):
	Constant(), value(value), initialized(!value.empty()), type(type) {}

/**
* @brief Destructs the constant.
*/
ConstArray::~ConstArray() {}

ShPtr<Value> ConstArray::clone() {
	if (isInitialized()) {
		ShPtr<ConstArray> constArray(ConstArray::create(value, type));
		constArray->setMetadata(getMetadata());
		return constArray;
	}
	ShPtr<ConstArray> constArray(ConstArray::createUninitialized(type));
	constArray->setMetadata(getMetadata());
	return constArray;
}

bool ConstArray::isEqualTo(ShPtr<Value> otherValue) const {
	// The types of compared instances have to match.
	ShPtr<ConstArray> otherConstArray = cast<ConstArray>(otherValue);
	if (!otherConstArray) {
		return false;
	}

	// The types have to match.
	if (getType() != otherConstArray->getType()) {
		return false;
	}

	// The initializations have to match.
	if (isInitialized() != otherConstArray->isInitialized()) {
		return false;
	}

	// Two uninitialized arrays are always equal.
	if (!isInitialized()) {
		return true;
	}

	// The number of indexes have to match.
	if (value.size() != otherConstArray->value.size()) {
		return false;
	}

	// All indexes have to match.
	for (ArrayValue::const_iterator i = value.begin(),
			j = otherConstArray->value.begin(), e = value.end(); i != e; ++i, ++j) {
		if (!(*i)->isEqualTo(*j)) {
			return false;
		}
	}

	return true;
}

ShPtr<Type> ConstArray::getType() const {
	return type;
}

void ConstArray::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	if (!isInitialized()) {
		// There is nothing to be done for uninitialized arrays.
		return;
	}

	// For each item in the array...
	for (auto &item : value) {
		if (item == oldExpr) {
			item = newExpr;
		} else {
			item->replace(oldExpr, newExpr);
		}
	}
}

/**
* @brief Returns the value of an initialized array.
*
* @par Preconditions
*  - the array is initialized
*
* @see isInitialized()
*/
const ConstArray::ArrayValue &ConstArray::getInitializedValue() const {
	PRECONDITION(isInitialized(), "the array is not initialized");

	return value;
}

/**
* @brief Returns an iterator to the first item of the initialized array.
*
* @par Preconditions
*  - the array is initialized
*
* @see isInitialized()
*/
ConstArray::init_iterator ConstArray::init_begin() const {
	PRECONDITION(isInitialized(), "the array is not initialized");

	return value.begin();
}

/**
* @brief Returns an iterator past the last item of the initialized array.
*
* @par Preconditions
*  - the array is initialized
*
* @see isInitialized()
*/
ConstArray::init_iterator ConstArray::init_end() const {
	PRECONDITION(isInitialized(), "the array is not initialized");

	return value.end();
}

/**
* @brief Returns @c true if the array is initialized, @c false otherwise.
*/
bool ConstArray::isInitialized() const {
	return initialized;
}

/**
* @brief Returns @c true if the array is empty, @c false otherwise.
*
* If the array is uninitialized, it needs to have no dimensions in order for
* this function to return @c true.
*/
bool ConstArray::isEmpty() const {
	if (isInitialized()) {
		return value.empty();
	} else {
		return type->hasEmptyDimensions();
	}
}

/**
* @brief Returns the type of items in the array.
*/
ShPtr<Type> ConstArray::getContainedType() const {
	return type->getContainedType();
}

/**
* @brief Returns the dimensions of the array.
*/
ArrayType::Dimensions ConstArray::getDimensions() const {
	return type->getDimensions();
}

/**
* @brief Creates an array constant initialized to the given value and type.
*
* @param[in] value Value of the constant.
* @param[in] type Type of the constant.
*
* @par Preconditions
*  - @a value is non-empty
*  - @a type is non-null
*/
ShPtr<ConstArray> ConstArray::create(ArrayValue value, ShPtr<ArrayType> type) {
	PRECONDITION(!value.empty(), "missing value for an initialized array");
	PRECONDITION_NON_NULL(type);

	ShPtr<ConstArray> array(new ConstArray(value, type));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	for (auto &item : value) {
		item->addObserver(array);
	}

	return array;
}

/**
* @brief Creates an uninitialized array constant of the given type.
*
* @param[in] type Type of the constant.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<ConstArray> ConstArray::createUninitialized(ShPtr<ArrayType> type) {
	PRECONDITION_NON_NULL(type);

	return ShPtr<ConstArray>(new ConstArray({}, type));
}

/**
* @brief Updates the array according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* It replaces @a subject with @arg. For example, if @a subject is an
* expression in the array, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any expression in the array
*  - @a arg is not an expression
*
* @par Preconditions
*  - both @a subject and @a arg are non-null
*
* @see Subject::update()
*/
void ConstArray::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newExpr = cast<Expression>(arg);
	if (!newExpr) {
		return;
	}

	// Go only through the initialized array (if there is something) because in
	// an uninitialized array, there is nothing to be replaced.
	for (auto &item : value) {
		if (item == subject) {
			item = newExpr;
		}
	}
}

void ConstArray::accept(Visitor *v) {
	v->visit(ucast<ConstArray>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
