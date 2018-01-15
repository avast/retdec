/**
* @file src/llvmir2hll/ir/void_type.cpp
* @brief Implementation of VoidType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new void type.
*
* See create() for more information.
*/
VoidType::VoidType():
	Type() {}

/**
* @brief Destructs the type.
*/
VoidType::~VoidType() {}

ShPtr<Value> VoidType::clone() {
	return VoidType::create();
}

bool VoidType::isEqualTo(ShPtr<Value> otherValue) const {
	return isa<VoidType>(otherValue);
}
/**
* @brief Returns the number of bits.
*/
std::size_t VoidType::getSize() const {
	return 0; // Size is 0.
}

/**
* @brief Creates a void type.
*
* The returned value is re-used, i.e. this function always returns the same
* instance.
*/
ShPtr<VoidType> VoidType::create() {
	static ShPtr<VoidType> createdType(new VoidType());
	return createdType;
}

void VoidType::accept(Visitor *v) {
	v->visit(ucast<VoidType>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
