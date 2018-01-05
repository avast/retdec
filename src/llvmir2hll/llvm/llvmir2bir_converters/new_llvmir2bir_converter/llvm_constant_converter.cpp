/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_constant_converter.cpp
* @brief Implementation of LLVMConstantConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/APFloat.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Type.h>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_constant_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_instruction_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_type_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/string_conversions.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/// Size of integral value storing index of structure element in bits.
/// It was chosen to use 32 bits because it is enough to store index
/// for huge structures.
const unsigned STRUCT_INDEX_SIZE_BITS = 32;

} // anonymous namespace

/**
* @brief Constructs a new converter.
*/
LLVMConstantConverter::LLVMConstantConverter(ShPtr<LLVMInstructionConverter> instConverter,
	ShPtr<LLVMTypeConverter> typeConverter):
	instConverter(instConverter), typeConverter(typeConverter) {}

/**
* @brief Destructs the converter.
*/
LLVMConstantConverter::~LLVMConstantConverter() {}

/**
* @brief Converts the given LLVM constant @a constant into an expression in BIR.
*
* @par Preconditions
*  - @a constant is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(llvm::Constant *constant) {
	PRECONDITION_NON_NULL(constant);

	if (auto cInt = llvm::dyn_cast<llvm::ConstantInt>(constant)) {
		return convertToExpression(cInt);
	} else if (auto cFloat = llvm::dyn_cast<llvm::ConstantFP>(constant)) {
		return convertToExpression(cFloat);
	} else if (auto cArray = llvm::dyn_cast<llvm::ConstantArray>(constant)) {
		return convertToExpression(cArray);
	} else if (auto cArray = llvm::dyn_cast<llvm::ConstantDataArray>(constant)) {
		return convertToExpression(cArray);
	} else if (auto cStruct = llvm::dyn_cast<llvm::ConstantStruct>(constant)) {
		return convertToExpression(cStruct);
	} else if (auto cpn = llvm::dyn_cast<llvm::ConstantPointerNull>(constant)) {
		return convertToExpression(cpn);
	} else if (auto globVar = llvm::dyn_cast<llvm::GlobalVariable>(constant)) {
		return convertToExpression(globVar);
	} else if (auto func = llvm::dyn_cast<llvm::Function>(constant)) {
		return getConverter()->convertValueToExpression(func);
	} else if (auto caz = llvm::dyn_cast<llvm::ConstantAggregateZero>(constant)) {
		return convertZeroInitializer(caz->getType());
	} else if (auto undef = llvm::dyn_cast<llvm::UndefValue>(constant)) {
		return convertZeroInitializer(undef->getType());
	} else if (auto cExpr = llvm::dyn_cast<llvm::ConstantExpr>(constant)) {
		return instConverter->convertConstExprToExpression(cExpr);
	}

	FAIL("unsupported constant: " << const_cast<llvm::Constant &>(*constant));
	return nullptr;
}

/**
* @brief Sets converter for LLVM values to the given @a conv.
*
* @par Preconditions
*  - @a conv is non-null
*/
void LLVMConstantConverter::setLLVMValueConverter(ShPtr<LLVMValueConverter> conv) {
	PRECONDITION_NON_NULL(conv);

	converter = conv;
}

/**
* @brief Converts the given LLVM boolean or integer constant @a cInt into
*        an expression in BIR.
*
* @par Preconditions
*  - @a cInt is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		const llvm::ConstantInt *cInt) {
	PRECONDITION_NON_NULL(cInt);

	if (isBool(cInt)) {
		return ConstBool::create(cInt->isOne());
	}

	return ConstInt::create(cInt->getValue());
}

/**
* @brief Converts the given LLVM floating point constant @a cFloat into
*        an expression in BIR.
*
* @par Preconditions
*  - @a cFloat is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		const llvm::ConstantFP *cFloat) {
	PRECONDITION_NON_NULL(cFloat);

	return ConstFloat::create(cFloat->getValueAPF());
}

/**
* @brief Converts the given LLVM constant array @a cArray into an expression
*        in BIR.
*
* Constant array consists of any type of constants, but for some specific
* constant arrays can be created LLVM types @c llvm::ConstantDataArray or @c
* llvm::ConstantAggregateZero. @c llvm::ConstantDataArray is created for array
* of simple constants like integers or floats and @c llvm::ConstantAggregateZero
* is created for zero initialized constant arrays.
*
* @par Preconditions
*  - @a cArray is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		llvm::ConstantArray *cArray) {
	PRECONDITION_NON_NULL(cArray);

	if (is8BitStringLiteral(cArray)) {
		return toConstString(cArray);
	}

	ConstArray::ArrayValue array;
	for (unsigned i = 0, e = cArray->getNumOperands(); i < e; ++i) {
		array.push_back(convertToExpression(cArray->getOperand(i)));
	}

	auto type = typeConverter->convert(cArray->getType());
	return ConstArray::create(array, type);
}

/**
* @brief Converts the given LLVM constant data array @a cArray into an expression
*        in BIR.
*
* Constant data array consists only of a simple elements, which means integer
* or floating point constants.
*
* @par Preconditions
*  - @a cArray is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		llvm::ConstantDataArray *cArray) {
	PRECONDITION_NON_NULL(cArray);

	if (cArray->isString()) {
		return toConstString(cArray);
	}

	ConstArray::ArrayValue array;
	for (unsigned i = 0, e = cArray->getNumElements(); i < e; ++i) {
		array.push_back(convertToExpression(cArray->getElementAsConstant(i)));
	}

	auto type = typeConverter->convert(cArray->getType());
	return ConstArray::create(array, type);
}

/**
* @brief Converts the given LLVM constant struct @a cStruct into an expression
*        in BIR.
*
* @par Preconditions
*  - @a cStruct is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		const llvm::ConstantStruct *cStruct) {
	PRECONDITION_NON_NULL(cStruct);

	ConstStruct::Type items;
	for (unsigned i = 0, e = cStruct->getNumOperands(); i < e; ++i) {
		auto elemName = getNameOfStructElement(i);
		auto elem = cStruct->getOperand(i);
		items.emplace_back(elemName, convertToExpression(elem));
	}

	auto type = typeConverter->convert(cStruct->getType());
	return ConstStruct::create(items, type);
}

/**
* @brief Converts the given LLVM null pointer constant @a cNullPtr into
*        an expression in BIR.
*
* @par Preconditions
*  - @a cNullPtr is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		const llvm::ConstantPointerNull *cNullPtr) {
	PRECONDITION_NON_NULL(cNullPtr);

	auto type = typeConverter->convert(cNullPtr->getType());
	return ConstNullPointer::create(type);
}

/**
* @brief Converts the given LLVM global value @a globVar into an expression in BIR.
*
* @par Preconditions
*  - @a globVar is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertToExpression(
		llvm::GlobalVariable *globVar) {
	PRECONDITION_NON_NULL(globVar);

	if (getConverter()->storesStringLiteral(*globVar)) {
		return getInitializerAsConstString(globVar);
	}

	return getConverter()->convertValueToExpression(globVar);
}

/**
* @brief Converts zero initialization of the given LLVM type @a type into
*        an expression in BIR.
*
* Zero initialization means that value is zero (for scalar types) or all values
* inside composite type are zeros.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertZeroInitializer(
		const llvm::Type *type) {
	PRECONDITION_NON_NULL(type);

	if (type->isIntegerTy()) {
		auto llvmIntType = llvm::cast<llvm::IntegerType>(type);
		return convertZeroInitializer(llvmIntType);
	} else if (type->isFloatingPointTy()) {
		auto llvmFPZero = llvm::APFloat::getZero(type->getFltSemantics());
		return ConstFloat::create(llvmFPZero);
	} else if (type->isArrayTy()) {
		auto llvmArrayType = llvm::cast<llvm::ArrayType>(type);
		return convertZeroInitializer(llvmArrayType);
	} else if (type->isStructTy()) {
		auto llvmStructType = llvm::cast<llvm::StructType>(type);
		return convertZeroInitializer(llvmStructType);
	} else if (type->isPointerTy()) {
		auto llvmPtrType = llvm::cast<llvm::PointerType>(type);
		return convertZeroInitializer(llvmPtrType);
	}

	FAIL("unsupported type for zeroinitializer: " << const_cast<llvm::Type &>(*type));
	return nullptr;
}

/**
* @brief Converts zero initialization of the given LLVM integer type @a type
*        into an expression in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertZeroInitializer(
		const llvm::IntegerType *type) {
	PRECONDITION_NON_NULL(type);

	if (typeConverter->isBool(type)) {
		return ConstBool::create(false);
	}

	return ConstInt::create(0, type->getIntegerBitWidth());
}

/**
* @brief Converts zero initialization of the given LLVM array type @a type into
*        an expression in BIR.
*
* Zero initialized array means that all values inside it are initialized to zeros.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertZeroInitializer(
		const llvm::ArrayType *type) {
	PRECONDITION_NON_NULL(type);

	return ConstArray::createUninitialized(typeConverter->convert(type));
}

/**
* @brief Converts zero initialization of the given LLVM struct type @a type into
*        an expression in BIR.
*
* Zero initialized struct means that all values inside it are initialized to
* zeros.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertZeroInitializer(
		const llvm::StructType *type) {
	PRECONDITION_NON_NULL(type);

	ConstStruct::Type items;
	unsigned i = 0;
	for (const auto &elemType: type->elements()) {
		auto fieldName = getNameOfStructElement(i++);
		auto value = convertZeroInitializer(elemType);
		items.emplace_back(fieldName, value);
	}

	auto birType = typeConverter->convert(type);
	return ConstStruct::create(items, birType);
}

/**
* @brief Converts zero initialization of the given LLVM pointer type @a type
*        into an expression in BIR. It created null pointer.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Expression> LLVMConstantConverter::convertZeroInitializer(
		const llvm::PointerType *type) {
	PRECONDITION_NON_NULL(type);

	return ConstNullPointer::create(typeConverter->convert(type));
}

/**
* @brief Determines if given LLVM integral constant @a cInt is boolean.
*
* @par Preconditions
*  - @a cInt is non-null
*/
bool LLVMConstantConverter::isBool(const llvm::ConstantInt *cInt) const {
	PRECONDITION_NON_NULL(cInt);

	return typeConverter->isBool(cInt->getType());
}

/**
* @brief Creates name of structure element with given index @a index.
*/
ShPtr<ConstInt> LLVMConstantConverter::getNameOfStructElement(unsigned index) const {
	return ConstInt::create(index, STRUCT_INDEX_SIZE_BITS);
}

/**
* @brief Returns the @c LLVMValueConverter.
*/
ShPtr<LLVMValueConverter> LLVMConstantConverter::getConverter() {
	auto conv = converter.lock();
	ASSERT_MSG(conv, "LLVMValueConverter has not been set or no longer exists");
	return conv;
}

} // namespace llvmir2hll
} // namespace retdec
