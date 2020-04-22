/**
 * @file include/retdec/bin2llvmir/optimizations/phi_remover/phi_remover.h
 * @brief Remove all Phi nodes (instructions).
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PHI_REMOVER_PHI_REMOVER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PHI_REMOVER_PHI_REMOVER_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class PhiRemover : public llvm::ModulePass
{
	public:
		static char ID;
		PhiRemover();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c);

	private:
		bool run();
		bool demotePhiToStack(
				llvm::PHINode* phi,
				llvm::MDNode* faddr);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
