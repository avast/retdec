/**
 * @file include/retdec/bin2llvmir/utils/ir_modifier.h
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H
#define RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class IrModifier
{
	public:
		using FunctionPair = std::pair<llvm::Function*, retdec::config::Function*>;
		using StackPair = std::pair<llvm::AllocaInst*, retdec::config::Object*>;

	public:
		IrModifier();
		IrModifier(llvm::Module* m, Config* c);

	public:
		FunctionPair renameFunction(
				llvm::Function* fnc,
				const std::string& fncName);
		FunctionPair splitFunctionOn(
				llvm::Instruction* inst,
				retdec::utils::Address start,
				const std::string& fncName = "");
		FunctionPair addFunction(
				retdec::utils::Address start,
				const std::string& fncName = "");
		FunctionPair addFunctionUnknown(retdec::utils::Address start);

		StackPair getStackVariable(
				llvm::Function* fnc,
				int offset,
				llvm::Type* type,
				const std::string& name = "stack_var");

	protected:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
