/**
* @file src/llvmir2hll/ir/struct_type.cpp
* @brief Implementation of StructType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstdint>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/conversion.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new structured type.
*
* See create() for more information.
*/
StructType::StructType(ElementTypes elementTypes, const std::string &name):
	Type(Value::ValueKind::StructType), elementTypes(elementTypes), name(name) {}

Value* StructType::clone() {
	return StructType::create(elementTypes);
}

bool StructType::isEqualTo(Value* otherValue) const {
	// All types have to be equal.
	if (StructType* otherStruct = cast<StructType>(otherValue)) {
		if (elementTypes == otherStruct->elementTypes &&
				name == otherStruct->name)
			return true;
	}
	return false;
}

/**
* @brief Returns @c true if the structure has a name, @c false otherwise.
*/
bool StructType::hasName() const {
	return !name.empty();
}

/**
* @brief Returns the name of the structure.
*
* If the structure has no name, the empty string is returned.
*/
const std::string &StructType::getName() const {
	return name;
}

/**
* @brief Returns the vector of elements in the structure.
*/
const StructType::ElementTypes &StructType::getElementTypes() const {
	return elementTypes;
}

/**
* @brief Returns the type of the given element.
*
* @par Preconditions
*  - there is a element on index @a index
*/
Type* StructType::getTypeOfElement(const ConstInt* index) const {
	std::uint64_t i = index->getValue().getZExtValue();
	PRECONDITION(i < elementTypes.size(),
		"there is no element on index " << i);
	return elementTypes[i];
}

/**
* @brief Creates a new structured type.
*
* @param elementTypes Types of elements in the structure.
* @param name Name of the structure (if any).
*/
StructType* StructType::create(ElementTypes elementTypes,
		const std::string &name) {
	return new StructType(elementTypes, name);
}

void StructType::accept(Visitor *v) {
	v->visit(ucast<StructType>(this));
}

} // namespace llvmir2hll
} // namespace retdec
