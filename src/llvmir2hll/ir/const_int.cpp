/**
* @file src/llvmir2hll/ir/const_int.cpp
* @brief Implementation of ConstInt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/string.h"

using retdec::utils::isComposedOnlyOfChars;
using retdec::utils::isComposedOnlyOfStrings;
using retdec::utils::toLower;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an integer constant initialized to the given value.
*
* See create() for more information.
*/
ConstInt::ConstInt(const llvm::APSInt &value):
	Constant(), value(value),
	type(IntType::create(value.getBitWidth(), value.isSigned())) {}

/**
* @brief Destructs the constant.
*/
ConstInt::~ConstInt() {}

ShPtr<Value> ConstInt::clone() {
	ShPtr<ConstInt> constInt(ConstInt::create(value));
	constInt->setMetadata(getMetadata());
	return constInt;
}

bool ConstInt::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values have to be equal.
	if (ShPtr<ConstInt> otherConstInt = cast<ConstInt>(otherValue)) {
		if (getType() != otherConstInt->getType()) { // Signed/unsigned included.
			return false;
		}
		return value == otherConstInt->value;
	}
	return false;
}

ShPtr<Type> ConstInt::getType() const {
	return type;
}

void ConstInt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Determines whether the constant has minimum signed value on it's bitwidth.
*
* @par Preconditions
*  - @a constant is signed.
*/
bool ConstInt::isMinSigned() const {
	PRECONDITION(isSigned(), "the constant is not signed");

	return getValue().isMinSignedValue();
}

/**
* @brief Returns @c true if the integer is signed, @c false otherwise.
*/
bool ConstInt::isSigned() const {
	return value.isSigned();
}

/**
* @brief Returns @c true if the integer is unsigned, @c false otherwise.
*/
bool ConstInt::isUnsigned() const {
	return !isSigned();
}

/**
* @brief Returns the constant's value.
*/
llvm::APSInt ConstInt::getValue() const {
	return value;
}

/**
* @brief Converts the constant into a string in the given @a radix and
*        optionally the given @a prefix.
*
* If the number is negative, like -5, instead of
* @code
* prefix-5
* @endcode
* this function returns
* @code
* -prefix5
* @endcode
*
* Alpha characters are printed in lower case. For example, @c 3899 decimal is
* converted into @c 0xf3b hexadecimal.
*
* @par Preconditions
*  - @a radix is 2, 8, 10, 16, or 36
*
* @see toHexString()
*/
std::string ConstInt::toString(unsigned radix, const std::string &prefix) const {
	PRECONDITION(radix == 2 || radix == 8 || radix == 10 || radix == 16 || radix == 36,
		"invalid radix " << radix);

	std::string asString(toLower(value.toString(radix, isSigned())));
	if (prefix.empty()) {
		return asString;
	}

	// For non-negative constants, we are done.
	if (asString[0] != '-') {
		return prefix + asString;
	}

	// For negative numbers, instead of prefix-X, we return -prefixX.
	return "-" + prefix + asString.substr(1);
}

/**
* @brief Converts the constant into a string in the hexadecimal format and
*        prepends the given @a prefix.
*
* Calling this function is equivalent to call
* @code
* toString(16, prefix);
* @endcode
* where @c prefix is by default @c "0x".
*
* @see toString()
*/
std::string ConstInt::toHexString(const std::string &prefix) const {
	return toString(16, prefix);
}

/**
* @brief Flip the sign of value.
*
* @par Preconditions
*  - @a constant is signed.
*  - @a constant is not minimal value on bitwidth.
*/
void ConstInt::flipSign() {
	PRECONDITION(isSigned(), "the constant is not signed");
	PRECONDITION(!isMinSigned(), "the constant is minimal value on bitwidth");

	value = getValue().operator -();
}

/**
* @brief Determines whether the constant is negative (< 0).
*/
bool ConstInt::isNegative() const {
	// Calling just getValue().isNegative() is not sufficient because this
	// method is from llvm::APInt, which doesn't include the information
	// whether the number of signed or unsigned. Therefore, we need to first
	// make sure that the number is signed, and then call isNegative().
	return isSigned() && getValue().isNegative();
}

/**
* @brief Determines whether the constant is negative one.
*
* @par Preconditions
*  - @a constant is signed.
*/
bool ConstInt::isNegativeOne() const {
	PRECONDITION(isSigned(), "the constant is not signed");

	return getValue().eq(llvm::APInt(getValue().getBitWidth(), -1, true));
}

/**
* @brief Determines whether the constant is positive (> 0).
*/
bool ConstInt::isPositive() const {
	return getValue().isStrictlyPositive();
}

/**
* @brief Determines whether the constant is zero.
*/
bool ConstInt::isZero() const {
	return getValue().eq(llvm::APInt(getValue().getBitWidth(), 0));
}

/**
* @brief Determines whether the constant is one.
*
* It returns @c true only for @c +1; for @c -1, it returns @c false.
*/
bool ConstInt::isOne() const {
	return getValue().eq(llvm::APInt(getValue().getBitWidth(), 1, isSigned()));
}

/**
* @brief Returns @c true if the constant is more readable in the hexadecimal
*        radix than in the decimal radix, @c false otherwise.
*
* A constant integer is more readable in the hexadecimal radix if its absolute
* value is greater than 4095 (the highest number representable on three bits)
* and satisfies any of the following conditions:
*  - it is of the form @c 0xYYY...Y, where @c Y is a hexadecimal digit.
*    Example: 0xfffffff (268435455).
*  - it is of the form @c 0xYZZ...Z, where @c Y and @c Z are hexadecimal digits.
*    Example: 0x1000000 (16777216).
*  - it is of the form @c 0xYZYZ... (possibly with an additional digit @c X at
*    the end), where @c Y and @c Z are hexadecimal digits. Example: 0xf0f0f0f
*    (252645135).
*  - it is of the form @c 0xYYZ...ZYY, where @c Y and @c Z are hexadecimal
*    digits. Example: 0xaa00aa (11141290).
*  - it is of the form @c 0xYYY...ZZZ, where @c Y and @c Z are hexadecimal
*    digits. Example: 0x111fff (1122303).
*/
bool ConstInt::isMoreReadableInHexa() const {
	std::string asHexaStr(toString(16));
	if (isNegative()) {
		// Remove the starting '-'.
		asHexaStr = asHexaStr.substr(1);
	}

	// If the number is lower than or equal to 4095 (the highest number
	// representable on three bits), it is not more readable (see the function
	// description).
	if (asHexaStr.length() <= 3) {
		return false;
	}

	// 0xYYY...Y
	if (isComposedOnlyOfChars(asHexaStr, asHexaStr[0])) {
		return true;
	}

	// 0xYZZ...Z
	if (isComposedOnlyOfChars(asHexaStr.substr(1), asHexaStr[1])) {
		return true;
	}

	// 0xYZYZ...
	if (isComposedOnlyOfStrings(asHexaStr, asHexaStr.substr(0, 2))) {
		return true;
	}

	// 0xYZYZ...X (an additional X at the end)
	if (isComposedOnlyOfStrings(asHexaStr.substr(0, asHexaStr.size() - 1),
			asHexaStr.substr(0, 2))) {
		return true;
	}

	// 0xYYZ...ZYY
	const char Y(asHexaStr[0]);
	std::string::size_type firstZPos(asHexaStr.find_first_not_of(Y));
	std::string::size_type lastZPos(asHexaStr.find_last_not_of(Y));
	if (firstZPos != std::string::npos && lastZPos != std::string::npos &&
			lastZPos != asHexaStr.size() - 1) {
		const char Z(asHexaStr[firstZPos]);
		std::string firstYs(asHexaStr.substr(0, firstZPos));
		std::string middleZs(asHexaStr.substr(firstZPos, lastZPos - firstZPos + 1));
		std::string lastYs(asHexaStr.substr(lastZPos + 1));
		if (firstYs == lastYs && isComposedOnlyOfChars(middleZs, Z)) {
			return true;
		}
	}

	// 0xYYY...ZZZ
	if (asHexaStr.length() % 2 != 0) {
		// Strings with odd length cannot be of the above form.
		return false;
	}
	std::string firstPart(asHexaStr.substr(0, asHexaStr.size() / 2));
	std::string secondPart(asHexaStr.substr(asHexaStr.size() / 2));
	if (isComposedOnlyOfChars(firstPart, firstPart[0]) &&
			isComposedOnlyOfChars(secondPart, secondPart[0])) {
		return true;
	}

	return false;
}

/**
* @brief Constructs an integer constant initialized to the given value of the
*        given bit width.
*
* @param[in] value Value of the constant.
* @param[in] bitWidth Bit width of the constant.
* @param[in] isSigned Is the value of the constant signed?
*
* This function should be used only for small constants, like -1, 0, 1, which
* always fit into int.
*/
ShPtr<ConstInt> ConstInt::create(std::int64_t value, unsigned bitWidth,
		bool isSigned) {
	return ConstInt::create(llvm::APInt(bitWidth, value, isSigned), isSigned);
}

/**
* @brief Constructs an integer constant initialized to the given value.
*
* @param[in] value Value of the constant.
* @param[in] isSigned Is the value of the constant signed?
*/
// Note: We cannot obtain the signed/unsigned information from llvm::APInt
//       because in an LLVM module, signed and unsigned constants are not
//       distinguished.
ShPtr<ConstInt> ConstInt::create(const llvm::APInt &value, bool isSigned) {
	// Since the second parameter of llvm::APSInt() is "isUnsigned", we have to
	// negate the value of isSigned.
	return ShPtr<ConstInt>(new ConstInt(llvm::APSInt(value, !isSigned)));
}

/**
* @brief Constructs an integer constant initialized to the given value.
*
* @param[in] value Value of the constant.
*/
ShPtr<ConstInt> ConstInt::create(const llvm::APSInt &value) {
	return ShPtr<ConstInt>(new ConstInt(value));
}

/**
* @brief Computes @c 2^x, where <tt>x >= 0</tt>, and returns the result.
*
* @par Preconditions
*  - @a x is non-null and <tt>>= 0</tt>
*/
ShPtr<ConstInt> ConstInt::getTwoToPositivePower(ShPtr<ConstInt> x) {
	PRECONDITION_NON_NULL(x);
	PRECONDITION(!x->isNegative(), "x, which is " << x << ", is not >= 0");

	// The power is implemented by 1 << x, which equals 2^x for x >= 0.
	return ConstInt::create(llvm::APInt(64, 1).shl(x->getValue()),
		x->isSigned());
}

void ConstInt::accept(Visitor *v) {
	v->visit(ucast<ConstInt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
