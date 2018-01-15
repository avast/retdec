/**
* @file src/llvmir2hll/ir/int_type.cpp
* @brief Implementation of IntType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new integer type.
*
* See create() for more information.
*/
IntType::IntType(unsigned size, bool isSigned):
	Type(), size(size), signedInt(isSigned) {}

/**
* @brief Destructs the type.
*/
IntType::~IntType() {}

ShPtr<Value> IntType::clone() {
	return IntType::create(size);
}

bool IntType::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and numbers of bits have to be equal.
	if (ShPtr<IntType> otherIntType = cast<IntType>(otherValue)) {
		return size == otherIntType->size;
	}
	return false;
}

/**
* @brief Returns the number of bits.
*/
unsigned IntType::getSize() const {
	return size;
}

/**
* @brief Returns @c true if the integer is signed, @c false otherwise.
*
* An integer can be either signed or unsigned.
*/
bool IntType::isSigned() const {
	return signedInt;
}

/**
* @brief Returns @c true if the integer is unsigned, @c false otherwise.
*
* An integer can be either signed or unsigned.
*/
bool IntType::isUnsigned() const {
	return !isSigned();
}

/**
* @brief Returns @c true if the type is bool, @c false otherwise.
*
* An integer type is bool if its size is 1.
*/
bool IntType::isBool() const {
	return size == 1;
}

/**
* @brief Creates a new integer type.
*
* @param[in] size Number of bits.
* @param[in] isSigned If @c true, the integer will be signed; otherwise, it
*                     will be unsigned.
*
* @par Preconditions
*  - @a size > 0
*/
ShPtr<IntType> IntType::create(unsigned size, bool isSigned) {
	PRECONDITION(size > 0, "invalid size " << size);

	// There are two maps, one for signed integers and one for unsigned integers.
	if (isSigned) {
		// To reduce the amount of created types, we use a set of already created
		// integer types of the given size. If the wanted type has already been
		// created, reuse it.
		auto it = createdSignedTypes.find(size);
		if (it != createdSignedTypes.end()) {
			return it->second;
		}
		// Create the type and store it for later use. There is no special
		// initialization.
		createdSignedTypes[size] = ShPtr<IntType>(new IntType(size, isSigned));
		return createdSignedTypes[size];
	} else {
		auto it = createdUnsignedTypes.find(size);
		if (it != createdUnsignedTypes.end()) {
			return it->second;
		}
		createdUnsignedTypes[size] = ShPtr<IntType>(new IntType(size, isSigned));
		return createdUnsignedTypes[size];
	}
}

void IntType::accept(Visitor *v) {
	v->visit(ucast<IntType>(shared_from_this()));
}

// Static variables and constants definitions.
std::map<unsigned, ShPtr<IntType>> IntType::createdSignedTypes;
std::map<unsigned, ShPtr<IntType>> IntType::createdUnsignedTypes;

} // namespace llvmir2hll
} // namespace retdec
