/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h
* @brief A converter from LLVM values to values in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_VALUE_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_VALUE_CONVERTER_H

#include <llvm/ADT/ArrayRef.h>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class CallInst;
class CompositeType;
class Constant;
class GlobalVariable;
class Instruction;
class Type;
class Value;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class CallExpr;
class Expression;
class LLVMConstantConverter;
class LLVMInstructionConverter;
class LLVMTypeConverter;
class Module;
class Type;
class Variable;
class VariablesManager;

/**
* @brief A converter from LLVM values to values in BIR.
*/
class LLVMValueConverter final: private retdec::utils::NonCopyable {
private:
	LLVMValueConverter(ShPtr<Module> resModule, ShPtr<VariablesManager> varManager);

public:
	~LLVMValueConverter();

	static ShPtr<LLVMValueConverter> create(ShPtr<Module> resModule,
		ShPtr<VariablesManager> varManager);

	/// @name Value conversion
	/// @{
	ShPtr<Expression> convertValueToDerefExpression(llvm::Value *value);
	ShPtr<Expression> convertValueToExpression(llvm::Value *value);
	ShPtr<Expression> convertValueToExpressionDirectly(llvm::Value *value);
	ShPtr<Variable> convertValueToVariable(llvm::Value *value);
	/// @}

	/// @name Type conversion
	/// @{
	ShPtr<Type> convertType(const llvm::Type *type);
	/// @}

	/// @name Constant conversion
	/// @{
	bool storesStringLiteral(const llvm::GlobalVariable &globVar) const;
	ShPtr<Expression> convertConstantToExpression(llvm::Constant *constant);
	/// @}

	/// @name Instruction conversion
	/// @{
	ShPtr<Expression> convertInstructionToExpression(llvm::Instruction *inst);
	ShPtr<CallExpr> convertCallInstToCallExpr(llvm::CallInst &inst);
	ShPtr<Expression> generateAccessToAggregateType(
		llvm::CompositeType *type, ShPtr<Expression> base,
		llvm::ArrayRef<unsigned> indices);
	/// @}

	/// @name Options
	/// @{
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

private:
	bool isConsideredAsPointer(const llvm::Value *value) const;
	bool shouldBeConvertedAsConst(const llvm::Constant *constant) const;
	bool shouldBeConvertedAsInst(const llvm::Instruction *inst) const;

	ShPtr<Type> determineVariableType(llvm::Value *value);

	/// A converter from LLVM type to type in BIR.
	ShPtr<LLVMTypeConverter> typeConverter;

	/// A converter from LLVM instruction to expression in BIR.
	ShPtr<LLVMInstructionConverter> instConverter;

	/// A converter from LLVM constant to constant in BIR.
	UPtr<LLVMConstantConverter> constConverter;

	/// Variables manager.
	ShPtr<VariablesManager> variablesManager;

	/// The resulting module in BIR.
	ShPtr<Module> resModule;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
