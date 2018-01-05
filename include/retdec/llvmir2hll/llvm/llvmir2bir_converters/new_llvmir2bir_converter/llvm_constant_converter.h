/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_constant_converter.h
* @brief A converter from LLVM constant to constant in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_CONSTANT_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_CONSTANT_CONVERTER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class ArrayType;
class Constant;
class ConstantArray;
class ConstantDataArray;
class ConstantFP;
class ConstantInt;
class ConstantPointerNull;
class ConstantStruct;
class GlobalVariable;
class IntegerType;
class PointerType;
class StructType;
class Type;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class ConstInt;
class Expression;
class LLVMInstructionConverter;
class LLVMTypeConverter;
class LLVMValueConverter;

/**
* @brief A converter from LLVM constant to constant in BIR.
*
* This converter handles only constant values, not constant expressions.
*
* @par Preconditions
*  - @c LLVMValueConverter must be set
*/
class LLVMConstantConverter final: private retdec::utils::NonCopyable {
public:
	LLVMConstantConverter(ShPtr<LLVMInstructionConverter> instConverter,
		ShPtr<LLVMTypeConverter> typeConverter);
	~LLVMConstantConverter();

	ShPtr<Expression> convertToExpression(llvm::Constant *constant);

	/// @name Options
	/// @{
	void setLLVMValueConverter(ShPtr<LLVMValueConverter> conv);
	/// @}

private:
	ShPtr<Expression> convertToExpression(const llvm::ConstantInt *cInt);
	ShPtr<Expression> convertToExpression(const llvm::ConstantFP *cFloat);
	ShPtr<Expression> convertToExpression(llvm::ConstantArray *cArray);
	ShPtr<Expression> convertToExpression(llvm::ConstantDataArray *cArray);
	ShPtr<Expression> convertToExpression(const llvm::ConstantStruct *cStruct);
	ShPtr<Expression> convertToExpression(const llvm::ConstantPointerNull *cNullPtr);
	ShPtr<Expression> convertToExpression(llvm::GlobalVariable *globVar);

	ShPtr<Expression> convertZeroInitializer(const llvm::Type *type);
	ShPtr<Expression> convertZeroInitializer(const llvm::IntegerType *type);
	ShPtr<Expression> convertZeroInitializer(const llvm::ArrayType *type);
	ShPtr<Expression> convertZeroInitializer(const llvm::StructType *type);
	ShPtr<Expression> convertZeroInitializer(const llvm::PointerType *type);

	bool isBool(const llvm::ConstantInt *cInt) const;
	ShPtr<ConstInt> getNameOfStructElement(unsigned index) const;

	ShPtr<LLVMValueConverter> getConverter();

	/// A converter from LLVM values to values in BIR.
	WkPtr<LLVMValueConverter> converter;

	/// A converter from LLVM instruction to expression in BIR.
	ShPtr<LLVMInstructionConverter> instConverter;

	/// A converter from LLVM type to type in BIR.
	ShPtr<LLVMTypeConverter> typeConverter;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
