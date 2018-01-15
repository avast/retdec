/**
* @file src/llvmir2hll/ir/string_type.cpp
* @brief Implementation of StringType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new string type.
*
* See create() for more information.
*/
StringType::StringType(std::size_t charSize):
	Type(), charSize(charSize) {}

/**
* @brief Destructs the type.
*/
StringType::~StringType() {}

ShPtr<Value> StringType::clone() {
	return StringType::create(charSize);
}

bool StringType::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and character sizes have to be equal.
	if (auto otherStringType = cast<StringType>(otherValue)) {
		return charSize == otherStringType->charSize;
	}
	return false;
}

/**
* @brief Returns how large are characters in the string (in bits).
*/
std::size_t StringType::getCharSize() const {
	return charSize;
}

/**
* @brief Creates a new string type.
*
* @param[in] charSize How large are characters in the string?
*
* @par Preconditions
*  - @a charSize > 0
*/
ShPtr<StringType> StringType::create(std::size_t charSize) {
	PRECONDITION(charSize > 0, "invalid charSize " << charSize);

	auto it = createdTypes.find(charSize);
	if (it != createdTypes.end()) {
		return it->second;
	}
	ShPtr<StringType> createdType(new StringType(charSize));
	createdTypes[charSize] = createdType;
	return createdType;
}

void StringType::accept(Visitor *v) {
	v->visit(ucast<StringType>(shared_from_this()));
}

// Static variables and constants definitions.
std::map<std::size_t, ShPtr<StringType>> StringType::createdTypes;

} // namespace llvmir2hll
} // namespace retdec
