/**
 * @file include/bin2llvmir/optimizations/provider_init/provider_init.h
 * @brief One time providers initialization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_OPTIMIZATIONS_PROVIDER_INIT_PROVIDER_INIT_H
#define BIN2LLVMIR_OPTIMIZATIONS_PROVIDER_INIT_PROVIDER_INIT_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace bin2llvmir {

class ProviderInitialization : public llvm::ModulePass
{
	public:
		static char ID;
		ProviderInitialization();
		virtual bool runOnModule(llvm::Module& m) override;
		virtual bool doFinalization(llvm::Module& m) override;
};

} // namespace bin2llvmir

#endif
