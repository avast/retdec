/**
* @file include/retdec/bin2llvmir/optimizations/register_localization/register_localization.h
* @brief Make all registers local.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_REGISTER_LOCALIZATION_REGISTER_LOCALIZATION_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_REGISTER_LOCALIZATION_REGISTER_LOCALIZATION_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class RegisterLocalization : public llvm::ModulePass
{
	public:
		static char ID;
		RegisterLocalization();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Abi* abi);

	private:
		bool run();

	private:
		llvm::Module* _module = nullptr;
		Abi* _abi = nullptr;
		static std::map<llvm::Type*, llvm::Function*> _type2fnc;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
