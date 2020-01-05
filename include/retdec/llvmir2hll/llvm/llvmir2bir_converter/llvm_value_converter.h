/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter/llvm_value_converter.h
* @brief A converter from LLVM values to values in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_LLVM_VALUE_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_LLVM_VALUE_CONVERTER_H

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
	LLVMValueConverter(Module* resModule, VariablesManager* varManager);

public:
	static LLVMValueConverter* create(Module* resModule,
		VariablesManager* varManager);

	/// @name Value conversion
	/// @{
	Expression* convertValueToDerefExpression(llvm::Value *value);
	Expression* convertValueToExpression(llvm::Value *value);
	Expression* convertValueToExpressionDirectly(llvm::Value *value);
	Variable* convertValueToVariable(llvm::Value *value);
	/// @}

	/// @name Type conversion
	/// @{
	Type* convertType(const llvm::Type *type);
	/// @}

	/// @name Constant conversion
	/// @{
	bool storesStringLiteral(const llvm::GlobalVariable &globVar) const;
	Expression* convertConstantToExpression(llvm::Constant *constant);
	/// @}

	/// @name Instruction conversion
	/// @{
	Expression* convertInstructionToExpression(llvm::Instruction *inst);
	CallExpr* convertCallInstToCallExpr(llvm::CallInst &inst);
	Expression* generateAccessToAggregateType(
		llvm::CompositeType *type, Expression* base,
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

	Type* determineVariableType(llvm::Value *value);

	/// A converter from LLVM type to type in BIR.
	LLVMTypeConverter* typeConverter = nullptr;

	/// A converter from LLVM instruction to expression in BIR.
	LLVMInstructionConverter* instConverter = nullptr;

	/// A converter from LLVM constant to constant in BIR.
	LLVMConstantConverter* constConverter = nullptr;

	/// Variables manager.
	VariablesManager* variablesManager = nullptr;

	/// The resulting module in BIR.
	Module* resModule = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
