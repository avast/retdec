/**
* @file src/llvmir2hll/ir/float_type.cpp
* @brief Implementation of FloatType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new float type.
*
* See create() for more information.
*/
FloatType::FloatType(unsigned size):
	Type(), size(size) {}

/**
* @brief Destructs the type.
*/
FloatType::~FloatType() {}

ShPtr<Value> FloatType::clone() {
	return FloatType::create(size);
}

bool FloatType::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and sizes have to be equal.
	if (ShPtr<FloatType> otherFloatType = cast<FloatType>(otherValue)) {
		return size == otherFloatType->size;
	}
	return false;
}

/**
* @brief Returns the number of bits.
*/
unsigned FloatType::getSize() const {
	return size;
}

/**
* @brief Returns true if exists type with size defined in args.
*
* @param[in] size Number of bits.
*
* @return Returns true if exists type, else false.
*/
bool FloatType::existsFloatTypeWith(unsigned size) const {
	return createdTypes.find(size) != createdTypes.end();
}

/**
* @brief Returns true if exists float type.
*
* @return Returns true if exists float type, else false.
*/
bool FloatType::existsFloatType() const {
	if (createdTypes.empty()) {
		return false;
	}
	return true;
}

/**
* @brief Creates a new float type.
*
* @param[in] size Number of bits.
*/
ShPtr<FloatType> FloatType::create(unsigned size) {
	PRECONDITION(size > 0, "invalid size " << size);

	// To reduce the amount of created types, we use a set of already created
	// float types of the given size. If the wanted type has already been
	// created, reuse it.
	auto it = createdTypes.find(size);
	if (it != createdTypes.end()) {
		return it->second;
	}

	// Create the type and store it for later use. There is no special
	// initialization.
	createdTypes[size] = ShPtr<FloatType>(new FloatType(size));
	return createdTypes[size];
}

void FloatType::accept(Visitor *v) {
	v->visit(ucast<FloatType>(shared_from_this()));
}

// Static variables and constants definitions.
std::map<unsigned, ShPtr<FloatType>> FloatType::createdTypes;

} // namespace llvmir2hll
} // namespace retdec
