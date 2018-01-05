/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_type_converter.cpp
* @brief Implementation of LLVMTypeConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_type_converter.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new converter.
*/
LLVMTypeConverter::LLVMTypeConverter(): mapLLVMTypeToType() {}

/**
* @brief Determines whether LLVM integral type @a type is boolean.
*
* @par Preconditions
*  - @a type is non-null
*/
bool LLVMTypeConverter::isBool(const llvm::IntegerType *type) const {
	PRECONDITION_NON_NULL(type);

	return type->getBitWidth() == 1;
}

/**
* @brief Converts the given LLVM type @a type into a type in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Type> LLVMTypeConverter::convert(const llvm::Type *type) {
	PRECONDITION_NON_NULL(type);

	auto existingTypeIt = mapLLVMTypeToType.find(type);
	if (existingTypeIt != mapLLVMTypeToType.end()) {
		return existingTypeIt->second;
	}

	ShPtr<Type> birType;
	if (type->isIntegerTy()) {
		birType = IntType::create(type->getIntegerBitWidth());
	} else if (type->isFloatingPointTy()) {
		birType = FloatType::create(type->getPrimitiveSizeInBits());
	} else if (type->isArrayTy()) {
		auto llvmArrayType = llvm::cast<llvm::ArrayType>(type);
		birType = convert(llvmArrayType);
	} else if (type->isStructTy()) {
		auto llvmStructType = llvm::cast<llvm::StructType>(type);
		birType = convert(llvmStructType);
	} else if (type->isPointerTy()) {
		auto llvmPtrType = llvm::cast<llvm::PointerType>(type);
		birType = convert(llvmPtrType);
	} else if (type->isFunctionTy()) {
		auto llvmFuncType = llvm::cast<llvm::FunctionType>(type);
		birType = convert(llvmFuncType);
	} else if (type->isVoidTy()) {
		birType = VoidType::create();
	} else {
		FAIL("unsupported type: " << const_cast<llvm::Type &>(*type));
	}

	// We need to store the converted type to prevent looping when converting
	// recursive types (containing pointers to the currently converted type).
	mapLLVMTypeToType.emplace(type, birType);

	return birType;
}

/**
* @brief Converts the given LLVM pointer type @a type into a pointer type in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<PointerType> LLVMTypeConverter::convert(const llvm::PointerType *type) {
	PRECONDITION_NON_NULL(type);

	auto birType = PointerType::create(UnknownType::create());
	mapLLVMTypeToType.emplace(type, birType);

	birType->setContainedType(convert(type->getElementType()));
	return birType;
}

/**
* @brief Converts the given LLVM array type @a type into a array type in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<ArrayType> LLVMTypeConverter::convert(const llvm::ArrayType *type) {
	PRECONDITION_NON_NULL(type);

	ArrayType::Dimensions arrayDims = {static_cast<std::size_t>(type->getNumElements())};

	auto elemTypeIt = type->getElementType();
	while (auto elemArrayType = llvm::dyn_cast<llvm::ArrayType>(elemTypeIt)) {
		arrayDims.push_back(elemArrayType->getNumElements());
		elemTypeIt = elemArrayType->getElementType();
	}

	auto elemType = convert(elemTypeIt);
	return ArrayType::create(elemType, arrayDims);
}

/**
* @brief Converts the given LLVM struct type @a type into a struct type in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<StructType> LLVMTypeConverter::convert(const llvm::StructType *type) {
	PRECONDITION_NON_NULL(type);

	StructType::ElementTypes elemTypes;
	for (const auto &elem: type->elements()) {
		elemTypes.push_back(convert(elem));
	}

	std::string name = type->hasName() ? type->getName() : "";
	return StructType::create(elemTypes, name);
}

/**
* @brief Converts the given LLVM function type @a type into a function type in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<FunctionType> LLVMTypeConverter::convert(const llvm::FunctionType *type) {
	PRECONDITION_NON_NULL(type);

	auto retType = convert(type->getReturnType());
	auto funcType = FunctionType::create(retType);

	for (const auto &argType: type->params()) {
		funcType->addParam(convert(argType));
	}

	if (type->isVarArg()) {
		funcType->setVarArg();
	}

	return funcType;
}

} // namespace llvmir2hll
} // namespace retdec
