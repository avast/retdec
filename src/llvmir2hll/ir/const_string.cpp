/**
* @file src/llvmir2hll/ir/const_string.cpp
* @brief Implementation of ConstString.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cctype>
#include <functional>
#include <iomanip>
#include <sstream>

#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a string constant initialized to the given value.
*
* See create() for more information.
*/
ConstString::ConstString(const UnderlyingStringType &value, std::size_t charSize):
	Constant(), value(value), charSize(charSize),
	type(StringType::create(charSize)) {}

/**
* @brief Destructs the constant.
*/
ConstString::~ConstString() {}

ShPtr<Value> ConstString::clone() {
	auto constString = ConstString::create(value, charSize);
	constString->setMetadata(getMetadata());
	return constString;
}

bool ConstString::isEqualTo(ShPtr<Value> otherValue) const {
	// Types, values, and character sizes have to be equal.
	if (auto otherConstString = cast<ConstString>(otherValue)) {
		return value == otherConstString->value &&
			charSize == otherConstString->charSize;
	}
	return false;
}

ShPtr<Type> ConstString::getType() const {
	return type;
}

void ConstString::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Returns the constant's value.
*/
ConstString::UnderlyingStringType ConstString::getValue() const {
	return value;
}

/**
* @brief Returns the constant's value as an escaped C string.
*/
std::string ConstString::getValueAsEscapedCString() const {
	return retdec::utils::asEscapedCString(value, charSize);
}

/**
* @brief Returns how large are characters in the string (in bits).
*/
std::size_t ConstString::getCharSize() const {
	return charSize;
}

/**
* @brief Is the string an 8-bit string?
*/
bool ConstString::is8BitString() const {
	return charSize == 8;
}

/**
* @brief Is the string a wide string?
*/
bool ConstString::isWideString() const {
	return charSize > 8;
}

/**
* @brief Constructs a string constant initialized to the given value.
*
* @param[in] value Value of the constant.
* @param[in] charSize How large are characters in the string (in bits)?
*
* @par Preconditions
*  - @a charSize is 8, 16, or 32
*/
ShPtr<ConstString> ConstString::create(const UnderlyingStringType &value,
		std::size_t charSize) {
	PRECONDITION(charSize == 8 || charSize == 16 || charSize == 32,
		"invalid charSize " << charSize);

	return ShPtr<ConstString>(new ConstString(value, charSize));
}

/**
* @brief Constructs a string constant initialized from the given 8-bit string.
*/
ShPtr<ConstString> ConstString::create(const std::string &str) {
	return create({str.begin(), str.end()}, 8);
}

void ConstString::accept(Visitor *v) {
	v->visit(ucast<ConstString>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
