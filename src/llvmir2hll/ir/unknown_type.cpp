/**
* @file src/llvmir2hll/ir/unknown_type.cpp
* @brief Implementation of UnknownType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new Unknown type.
*
* See create() for more information.
*/
UnknownType::UnknownType():
	Type() {}

/**
* @brief Destructs the type.
*/
UnknownType::~UnknownType() {}

ShPtr<Value> UnknownType::clone() {
	return UnknownType::create();
}

bool UnknownType::isEqualTo(ShPtr<Value> otherValue) const {
	return isa<UnknownType>(otherValue);
}

/**
* @brief Returns the number of bits.
*
* @return Returns size 0.
*
*/
std::size_t UnknownType::getSize() const {
	return 0; // Size is 0.
}

/**
* @brief Creates a new unknown type.
*
* The returned value is re-used, i.e. this function always returns the same
* instance.
*/
ShPtr<UnknownType> UnknownType::create() {
	static ShPtr<UnknownType> createdType(new UnknownType());
	return createdType;
}

void UnknownType::accept(Visitor *v) {
	v->visit(ucast<UnknownType>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
