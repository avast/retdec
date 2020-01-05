/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter/llvm_constant_converter.h
* @brief A converter from LLVM constant to constant in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_LLVM_CONSTANT_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_LLVM_CONSTANT_CONVERTER_H

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
	LLVMConstantConverter(LLVMInstructionConverter* instConverter,
		LLVMTypeConverter* typeConverter);

	Expression* convertToExpression(llvm::Constant *constant);

	/// @name Options
	/// @{
	void setLLVMValueConverter(LLVMValueConverter* conv);
	/// @}

private:
	Expression* convertToExpression(const llvm::ConstantInt *cInt);
	Expression* convertToExpression(const llvm::ConstantFP *cFloat);
	Expression* convertToExpression(llvm::ConstantArray *cArray);
	Expression* convertToExpression(llvm::ConstantDataArray *cArray);
	Expression* convertToExpression(const llvm::ConstantStruct *cStruct);
	Expression* convertToExpression(const llvm::ConstantPointerNull *cNullPtr);
	Expression* convertToExpression(llvm::GlobalVariable *globVar);

	Expression* convertZeroInitializer(const llvm::Type *type);
	Expression* convertZeroInitializer(const llvm::IntegerType *type);
	Expression* convertZeroInitializer(const llvm::ArrayType *type);
	Expression* convertZeroInitializer(const llvm::StructType *type);
	Expression* convertZeroInitializer(const llvm::PointerType *type);

	bool isBool(const llvm::ConstantInt *cInt) const;
	ConstInt* getNameOfStructElement(unsigned index) const;

	LLVMValueConverter* getConverter();

	/// A converter from LLVM values to values in BIR.
	LLVMValueConverter* converter = nullptr;

	/// A converter from LLVM instruction to expression in BIR.
	LLVMInstructionConverter* instConverter = nullptr;

	/// A converter from LLVM type to type in BIR.
	LLVMTypeConverter* typeConverter = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
