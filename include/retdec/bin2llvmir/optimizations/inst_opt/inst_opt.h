/**
* @file include/retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h
* @brief Instruction optimizations which we want to do ourselves.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_INST_OPT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_INST_OPT_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Our own instruction optimizer.
 * We want to do some general (not related to any particular analysis)
 * instruction optimizations on our own, either because LLVM will not perform
 * them at all, or because it works on protected (volatilized) load/store
 * operations which can not be optimized by LLVM passes.
 */
class InstOpt : public llvm::ModulePass
{
	public:
		static char ID;
		InstOpt();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Config* c = nullptr);

	private:
		void removeInstructionNames();
		bool run();
		bool runGeneralOpts();
		bool fixX86RepAnalysis();

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
