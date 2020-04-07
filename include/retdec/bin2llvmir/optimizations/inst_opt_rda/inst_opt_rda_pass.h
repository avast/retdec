/**
 * @file include/retdec/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda_pass.h
 * @brief LLVM instruction optimization pass using RDA.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_RDA_INST_OPT_RDA_PASS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_RDA_INST_OPT_RDA_PASS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class InstructionRdaOptimizer : public llvm::ModulePass
{
	public:
		static char ID;
		InstructionRdaOptimizer();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Abi* abi);

	private:
		bool run();
		bool runOnFunction(llvm::Function* f);

	private:
		llvm::Module* _module = nullptr;
		Abi* _abi = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif