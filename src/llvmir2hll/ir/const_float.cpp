/**
* @file src/llvmir2hll/ir/const_float.cpp
* @brief Implementation of ConstFloat.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/SmallVector.h>

#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/string.h"

using retdec::utils::startsWith;
using retdec::utils::toLower;
using retdec::utils::trim;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Computes the type of the given llvm::APFloat.
*/
ShPtr<FloatType> getTypeOfValue(const ConstFloat::Type &value) {
	// FloatType::create() needs the size of the type in bits. The size has to
	// be obtained from the semantics. However, I haven't found a better way of
	// doing this because you cannot simply obtain the size from the semantics
	// because the semantics is not a publicly accessible type.
	// The sizes are based on http://llvm.org/docs/LangRef.html#floating-point-types.
	unsigned size = 0;
	const auto &semantics = value.getSemantics();
	if (&semantics == &llvm::APFloat::IEEEhalf) {
		size = 16;
	} else if (&semantics == &llvm::APFloat::IEEEsingle) {
		size = 32;
	} else if (&semantics == &llvm::APFloat::IEEEdouble) {
		size = 64;
	} else if (&semantics == &llvm::APFloat::IEEEquad) { // fp128
		size = 128;
	} else if (&semantics == &llvm::APFloat::x87DoubleExtended) { // x86_fp80
		size = 80;
	} else if (&semantics == &llvm::APFloat::PPCDoubleDouble) { // ppc_fp128
		size = 128;
	} else {
		FAIL("unsupported semantics of llvm::APFloat");
	}
	return FloatType::create(size);
}

} // anonymous namespace

/**
* @brief Constructs a float constant initialized to the given value.
*
* See create() for more information.
*/
ConstFloat::ConstFloat(Type value):
	Constant(), value(value), type(getTypeOfValue(value)) {}

/**
* @brief Destructs the constant.
*/
ConstFloat::~ConstFloat() {}

ShPtr<Value> ConstFloat::clone() {
	ShPtr<ConstFloat> constFloat(ConstFloat::create(value));
	constFloat->setMetadata(getMetadata());
	return constFloat;
}

bool ConstFloat::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values have to be equal.
	if (ShPtr<ConstFloat> otherConstFloat = cast<ConstFloat>(otherValue)) {
		if (getType() != otherConstFloat->getType()) {
			return false;
		}
		return value.compare(otherConstFloat->value) == llvm::APFloat::cmpEqual;
	}
	return false;
}

ShPtr<Type> ConstFloat::getType() const {
	return type;
}

void ConstFloat::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Returns the constant's value.
*/
ConstFloat::Type ConstFloat::getValue() const {
	return value;
}

/**
* @brief Returns the number of bits of the constant's type.
*/
unsigned ConstFloat::getSize() const {
	return type->getSize();
}

/**
* @brief Converts the constant into a decimal string.
*
* The description of this function has been taken from the description of
* llvm::APFloat::toString().
*
* @param[in] precision The maximum number of digits of precision to output. If
*            there are fewer digits available, zero padding will not be used
*            unless the value is integral and small enough to be expressed in
*            @a precision digits. 0 means to use the natural precision of the
*            number.
* @param[in] maxPadding The maximum number of zeros to consider inserting
*            before falling back to scientific notation. 0 means to always use
*            scientific notation.
*
* @code
* Number       Precision    MaxPadding      Result
* ------       ---------    ----------      ------
* 1.01e+4              5             2       10100
* 1.01e+4              4             2       1.01e+4
* 1.01e+4              5             1       1.01e+4
* 1.01e-2              5             2       0.0101
* 1.01e-2              4             2       0.0101
* 1.01e-2              4             1       1.01e-2
* @endcode
*
* The resulting string has all characters lowercase.
*/
std::string ConstFloat::toString(unsigned precision, unsigned maxPadding) const {
	// TODO Is there a better way of doing this? I have found no other way.

	// TODO Is the size 1024 below sufficient?
	llvm::SmallVector<char, 1024> strV;
	value.toString(strV, precision, maxPadding);
	std::string str(strV.begin(), strV.end());

	// TODO When converting special cases, like 0 or NaN, `X \0` is obtained
	//      instead of `X`. Why is this happening? Anyway, we have to fix this.
	if (str.back() == '\0') {
		str = trim(str.substr(0, str.size() - 1));
	}

	// Convert all letters to lowercase (1.2E5 -> 1.2e5, Inf -> inf etc.).
	return toLower(str);
}

/**
* @brief Converts the constant into the most readable decimal representation.
*
* If you want to have a finer control of the resulting form, use toString().
*/
std::string ConstFloat::toMostReadableString() const {
	ToStringArgs toStringArgs(getToStringArgsForMostReadableString());
	std::string asString(toString(toStringArgs.first, toStringArgs.second));

	// For X.0, the above call to toString() returns X. We want X.0 instead.
	if (asString.find_first_of(".eni") == std::string::npos) {
		asString += ".0";
	}

	// Instead of -0.0, we want 0.0.
	if (isZero() && startsWith(asString, "-")) {
		asString = asString.substr(1);
	}

	return asString;
}

/**
* @brief Returns the arguments for which toString() returns the most readable
*        string.
*/
ConstFloat::ToStringArgs ConstFloat::getToStringArgsForMostReadableString() const {
	// Allow to insert at most 3 zeros before falling to scientific notation
	// (maxPadding).
	unsigned maxPadding = 3;

	// Since LLVM 3.4, some floats are represented imprecisely when using
	// toString() with precision equal to zero (= natural representation):
	//
	//     0.24 -> 0.23999999999999999
	//     7.4  -> 7.4000000000000004
	//
	// Therefore, we try to use toString() with such precision so that we do
	// not loose precision when it is not absolutely necessary and produce the
	// most readable result.
	//
	// The numbers below have been obtained by experimenting with the produced
	// results with various precisions and padding.
	//
	// The used approach is messy, but I was unable to find a better way.
	unsigned precision = 0; // Do not limit the precision.
	std::string asString(toString(precision, maxPadding));
	if (asString.find("000000") != std::string::npos ||
			asString.find("999999") != std::string::npos) {
		precision = 8; // Limit the precision.
	}

	return ToStringArgs(precision, maxPadding);
}

/**
* @brief Flip the sign of value.
*/
void ConstFloat::flipSign() {
	llvm::APFloat apFloat = getValue();
	apFloat.changeSign();
	value = apFloat;
}

/**
* @brief Determines whether the float constant is negative (< 0).
*/
bool ConstFloat::isNegative() const {
	// !isNegZero() because isNegative() returns true for -0.0.
	return getValue().isNegative() && !getValue().isNegZero();
}

/**
* @brief Determines whether the float constant is negative one.
*/
bool ConstFloat::isNegativeOne() const {
	return isEqualTo(ConstFloat::create(llvm::APFloat(getValue().
		getSemantics(), "-1.0")));
}

/**
* @brief Determines whether the float constant is positive (> 0).
*/
bool ConstFloat::isPositive() const {
	return (!getValue().isNegative() && !getValue().isZero());
}

/**
* @brief Determines whether the float constant is zero.
*/
bool ConstFloat::isZero() const {
	return getValue().isZero();
}

/**
* @brief Constructs a float constant initialized to the given value.
*
* @param[in] value Value of the constant.
*/
ShPtr<ConstFloat> ConstFloat::create(Type value) {
	return ShPtr<ConstFloat>(new ConstFloat(value));
}

void ConstFloat::accept(Visitor *v) {
	v->visit(ucast<ConstFloat>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
