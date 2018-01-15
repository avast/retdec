/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.cpp
* @brief Implementation of LLVMValueConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalObject.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_constant_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_instruction_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_type_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/variables_manager.h"
#include "retdec/llvmir2hll/llvm/string_conversions.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new converter.
*
* @param[in] resModule The resulting module in BIR.
* @param[in] varManager Variable manager managing local variables of currently
*                       converted function.
*/
LLVMValueConverter::LLVMValueConverter(ShPtr<Module> resModule,
	ShPtr<VariablesManager> varManager):
		typeConverter(std::make_shared<LLVMTypeConverter>()),
		instConverter(std::make_shared<LLVMInstructionConverter>()),
		constConverter(std::make_unique<LLVMConstantConverter>(
			instConverter, typeConverter)),
		variablesManager(varManager),
		resModule(resModule) {}

/**
* @brief Destructs the converter.
*/
LLVMValueConverter::~LLVMValueConverter() {}

/**
* @brief Creates a new converter.
*
* @param[in] resModule The resulting module in BIR.
* @param[in] varManager Variable manager managing local variables of currently
*                       converted function.
*/
ShPtr<LLVMValueConverter> LLVMValueConverter::create(ShPtr<Module> resModule,
		ShPtr<VariablesManager> varManager) {
	PRECONDITION_NON_NULL(resModule);
	PRECONDITION_NON_NULL(varManager);

	ShPtr<LLVMValueConverter> converter(new LLVMValueConverter(resModule, varManager));
	converter->instConverter->setLLVMValueConverter(converter);
	converter->constConverter->setLLVMValueConverter(converter);
	return converter;
}

/**
* @brief Converts the given LLVM value @a value into a dereference
*        expression in BIR.
*
* If converted value @a value is not considered as pointer, it returns value
* converted into an expression in BIR as is (value is not converted into
* dereference expression).
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<Expression> LLVMValueConverter::convertValueToDerefExpression(
		llvm::Value *value) {
	PRECONDITION_NON_NULL(value);

	auto expr = convertValueToExpressionDirectly(value);
	if (!isConsideredAsPointer(value)) {
		return expr;
	} else if (auto addressOpExpr = cast<AddressOpExpr>(expr)) {
		return addressOpExpr->getOperand();
	}

	return DerefOpExpr::create(expr);
}

/**
* @brief Converts the given LLVM value @a value into an expression in BIR.
*
* If converted value @a value is not considered as pointer, it returns address
* operand of value converted to an expression in BIR (pointer to value must be
* created).
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<Expression> LLVMValueConverter::convertValueToExpression(llvm::Value *value) {
	PRECONDITION_NON_NULL(value);

	auto expr = convertValueToExpressionDirectly(value);
	if (!isa<ConstString>(expr) && !isConsideredAsPointer(value)) {
		expr = AddressOpExpr::create(expr);
	}

	return expr;
}

/**
* @brief Converts the given LLVM value @a value into an expression in BIR.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<Expression> LLVMValueConverter::convertValueToExpressionDirectly(
		llvm::Value *value) {
	PRECONDITION_NON_NULL(value);

	if (auto constant = llvm::dyn_cast<llvm::Constant>(value)) {
		if (shouldBeConvertedAsConst(constant)) {
			return convertConstantToExpression(constant);
		}
	} else if (auto inst = llvm::dyn_cast<llvm::Instruction>(value)) {
		if (shouldBeConvertedAsInst(inst)) {
			return convertInstructionToExpression(inst);
		}
	}

	return convertValueToVariable(value);
}

/**
* @brief Converts the given LLVM value @a value into a variable in BIR.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<Variable> LLVMValueConverter::convertValueToVariable(llvm::Value *value) {
	PRECONDITION_NON_NULL(value);

	auto var = variablesManager->getVarByValue(value);
	if (isa<UnknownType>(var->getType())) {
		var->setType(determineVariableType(value));
	}

	return var;
}

/**
* @brief Converts the given LLVM type @a type into a type in BIR.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Type> LLVMValueConverter::convertType(const llvm::Type *type) {
	PRECONDITION_NON_NULL(type);

	return typeConverter->convert(type);
}

/**
* @brief Determines whether the given LLVM global variable @a globVar stores
*        string literal.
*/
bool LLVMValueConverter::storesStringLiteral(
		const llvm::GlobalVariable &globVar) const {
	return resModule->isGlobalVarStoringStringLiteral(globVar.getName())
		|| stores8BitStringLiteral(&globVar);
}

/**
* @brief Converts the given LLVM constant @a constant into an expression in BIR.
*
* @par Preconditions
*  - @a constant is non-null
*/
ShPtr<Expression> LLVMValueConverter::convertConstantToExpression(
		llvm::Constant *constant) {
	PRECONDITION_NON_NULL(constant);

	return constConverter->convertToExpression(constant);
}

/**
* @brief Converts the given LLVM instruction @a inst into an expression in BIR.
*
* @par Preconditions
*  - @a inst is non-null
*/
ShPtr<Expression> LLVMValueConverter::convertInstructionToExpression(
		llvm::Instruction *inst) {
	PRECONDITION_NON_NULL(inst);

	return instConverter->convertInstructionToExpression(inst);
}

/**
* @brief Converts the given LLVM call instruction @a inst into an expression in BIR.
*/
ShPtr<CallExpr> LLVMValueConverter::convertCallInstToCallExpr(llvm::CallInst &inst) {
	return instConverter->convertCallInstToCallExpr(inst);
}

/**
* @brief Generates access to aggregate type as a part of conversion of LLVM
*        instruction insertvalue or extractvalue.
*
* @param[in] type Type of aggregate type.
* @param[in] base Base expression.
* @param[in] indices Array of indices.
*/
ShPtr<Expression> LLVMValueConverter::generateAccessToAggregateType(
		llvm::CompositeType *type, ShPtr<Expression> base,
		llvm::ArrayRef<unsigned> indices) {
	return instConverter->generateAccessToAggregateType(type, base, indices);
}

/**
* @brief Enables/disables the use of strict FPU semantics.
*
* @param[in] strict If @c true, enables the use of strict FPU semantics. If @c
*                   false, disables the use of strict FPU semantics.
*/
void LLVMValueConverter::setOptionStrictFPUSemantics(bool strict) {
	instConverter->setOptionStrictFPUSemantics(strict);
}

/**
* @brief Determines whether the given LLVM @a value is considered as pointer
*        variable.
*
* @par Preconditions
*  - @a value is non-null
*/
bool LLVMValueConverter::isConsideredAsPointer(const llvm::Value *value) const {
	PRECONDITION_NON_NULL(value);

	return !LLVMSupport::isDirectAlloca(value)
		&& !llvm::isa<llvm::GlobalVariable>(value);
}

/**
* @brief Determines whether the given LLVM constant @a constant should be
*        converted into BIR as constant.
*
* @par Preconditions
*  - @a constant is non-null
*/
bool LLVMValueConverter::shouldBeConvertedAsConst(const llvm::Constant *constant) const {
	PRECONDITION_NON_NULL(constant);

	if (auto globVar = llvm::dyn_cast<llvm::GlobalVariable>(constant)) {
		if (storesStringLiteral(*globVar)) {
			return true;
		}
	}

	return !llvm::isa<llvm::GlobalObject>(constant);
}

/**
* @brief Determines whether the given LLVM instruction @a inst should be
*        converted into BIR as instruction.
*
* This means that we don't want into convert all LLVM instruction into BIR
* instructions. Some instruction may be converted e.g. into variables.
*
* @par Preconditions
*  - @a inst is non-null
*/
bool LLVMValueConverter::shouldBeConvertedAsInst(const llvm::Instruction *inst) const {
	PRECONDITION_NON_NULL(inst);

	return LLVMSupport::isInlinableInst(inst)
		&& !llvm::isa<llvm::AllocaInst>(inst);
}

/**
* @brief Determines the correct type of the given LLVM value @a value.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<Type> LLVMValueConverter::determineVariableType(llvm::Value *value) {
	PRECONDITION_NON_NULL(value);

	if (auto allocaInst = LLVMSupport::isDirectAlloca(value)) {
		return typeConverter->convert(allocaInst->getAllocatedType());
	} else if (auto globVar = llvm::dyn_cast<llvm::GlobalVariable>(value)) {
		return typeConverter->convert(globVar->getType()->getElementType());
	}

	return typeConverter->convert(value->getType());
}

} // namespace llvmir2hll
} // namespace retdec
