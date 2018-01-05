/**
* @file src/llvmir2hll/llvm/string_conversions.cpp
* @brief Implementation of string conversions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstdint>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>

#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/llvm/string_conversions.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Returns how large are characters in the given type.
*
* @par Preconditions
*  - @c type is an instance of @c llvm::SequentialType and stores characters
*    (of arbitrary length)
*/
std::size_t getCharSize(const llvm::Type *type) {
	auto arrayType = llvm::dyn_cast<llvm::SequentialType>(type);
	PRECONDITION(arrayType, "expected type to be llvm::SequentialType");
	return arrayType->getElementType()->getPrimitiveSizeInBits();
}

} // anonymous namespace

/**
* @brief Checks if the given LLVM constant array represents an 8-bit string
*        literal.
*/
bool is8BitStringLiteral(const llvm::ConstantArray *ca) {
	// A string cannot be empty (there at least has to be the null byte).
	if (!ca) {
		return false;
	}

	// Check if ca is an array of ubytes or an array of sbytes with positive
	// values.
	llvm::Type *elemType = ca->getType()->getElementType();
	if (elemType != llvm::Type::getInt8Ty(ca->getContext())) {
		return false;
	}

	// Make sure the last character is a null byte, as automatically added by C.
	if (ca->getNumOperands() == 0 ||
			!llvm::cast<llvm::Constant>(*(ca->op_end() - 1))->isNullValue()) {
		return false;
	}

	// It represents a string.
	return true;
}

/**
* @brief Checks if the global variable stores an 8-bit string literal.
*
* @par Preconditions
*  - @a v is non-null
*/
bool stores8BitStringLiteral(const llvm::GlobalVariable *v) {
	PRECONDITION_NON_NULL(v);

	// It has to a constant. If it is not, it cannot store a string literal.
	if (!v->isConstant()) {
		return false;
	}

	// The empty string ("") may be represented by a global variable with
	// either no initializer or a zero initializer:
	//
	//   @str = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
	//
	//   define i32 @main() {
	//   bb:
	//     %tmp = call i32 (i8*, ...)* @printf(i8* getelementptr inbounds (
	//                                         [1 x i8]* @str, i64 0, i64 0))
	//     ret i32 0
	//   }
	//
	// To this end, if the variable has either no or the zero initializer, it
	// stores a string literal if and only if its type is an array of i8.
	if (!v->hasInitializer() || v->getInitializer()->isNullValue()) {
		// The array of i8 has to actually be [Y x i8]*, i.e. a pointer to an
		// array of i8.
		if (llvm::PointerType *ptrType =
				llvm::dyn_cast<llvm::PointerType>(v->getType())) {
			if (llvm::ArrayType *arrayType =
					llvm::dyn_cast<llvm::ArrayType>(ptrType->getElementType())) {
				if (llvm::Type *elemType =
						arrayType->getArrayElementType()) {
					return elemType == llvm::Type::getInt8Ty(arrayType->getContext());
				}
			}
		}
		return false;
	}

	// String literals can be represented by either llvm::ConstantArray or
	// llvm::ConstantDataArray. The latter has a isString() member function,
	// unlike the former, for which we have to use a custom function.
	if (auto ca = llvm::dyn_cast<llvm::ConstantArray>(v->getInitializer())) {
		return is8BitStringLiteral(ca);
	} else if (auto cda = llvm::dyn_cast<llvm::ConstantDataArray>(v->getInitializer())) {
		return cda->isString();
	}

	return false;
}

/**
* @brief Converts the given LLVM constant array into ConstString.
*
* @par Preconditions
*  - @a ca is non-null and represents a constant string
*/
ShPtr<ConstString> toConstString(llvm::ConstantArray *ca) {
	PRECONDITION_NON_NULL(ca);

	ConstString::UnderlyingStringType strValue;
	// Do not append the last character, which we know is the null byte.
	for (unsigned i = 0, e = ca->getNumOperands() - 1; i != e; ++i) {
		strValue.push_back(
			llvm::cast<llvm::ConstantInt>(ca->getOperand(i))->getZExtValue()
		);
	}
	return ConstString::create(strValue, getCharSize(ca->getType()));
}

/**
* @brief Converts the given LLVM constant data array into ConstString.
*
* @par Preconditions
*  - @a cda is non-null and represents a constant string
*/
ShPtr<ConstString> toConstString(llvm::ConstantDataArray *cda) {
	PRECONDITION_NON_NULL(cda);

	// Do not include the last element if it is the null byte (\x00) because in
	// C, every string literal automatically ends with the null byte.
	unsigned numOfElements = cda->getNumElements();
	if (cda->getElementAsInteger(numOfElements - 1) == 0) {
		numOfElements--;
	}

	// Convert it into a string.
	ConstString::UnderlyingStringType strValue;
	for (unsigned i = 0; i < numOfElements; ++i) {
		strValue.push_back(cda->getElementAsInteger(i));
	}
	return ConstString::create(strValue, getCharSize(cda->getType()));
}

/**
* @brief Returns the initializer of the given global variable as ConstString.
*/
ShPtr<ConstString> getInitializerAsConstString(llvm::GlobalVariable *v) {
	if (!v->hasInitializer() || v->getInitializer()->isNullValue()) {
		// There is no initializer, which means it is the empty string.
		return ConstString::create({}, getCharSize(v->getType()->getContainedType(0)));
	}

	// There is an initializer. The string literal itself may be stored in
	// either a ConstantDataArray or a ConstantArray.
	llvm::Constant *init = v->getInitializer();
	if (llvm::ConstantDataArray *cda = llvm::dyn_cast<llvm::ConstantDataArray>(init)) {
		return toConstString(cda);
	} else if (llvm::ConstantArray *ca = llvm::dyn_cast<llvm::ConstantArray>(init)) {
		return toConstString(ca);
	}

	FAIL("unsupported type for a string literal (`" << *init << "`)");
	return ConstString::create("?");
}

} // namespace llvmir2hll
} // namespace retdec
