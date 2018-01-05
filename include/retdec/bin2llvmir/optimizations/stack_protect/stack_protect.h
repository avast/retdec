/**
* @file include/retdec/bin2llvmir/optimizations/stack_protect/stack_protect.h
* @brief Protect stack variables from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_PROTECT_STACK_PROTECT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_PROTECT_STACK_PROTECT_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class StackProtect : public llvm::ModulePass
{
	public:
		static char ID;
		StackProtect();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c);

	private:
		bool run();
		bool protectStack();
		bool unprotectStack(llvm::Function* fnc);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;

		std::string _fncName = "__decompiler_undefined_function_";
		static std::map<llvm::Type*, llvm::Function*> _type2fnc;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
