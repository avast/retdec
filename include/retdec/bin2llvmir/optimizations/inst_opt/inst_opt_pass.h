/**
 * @file include/retdec/bin2llvmir/optimizations/inst_opt/inst_opt_pass.h
 * @brief LLVM instruction optimization pass.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_INST_OPT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_INST_OPT_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class InstructionOptimizer : public llvm::ModulePass
{
	public:
		static char ID;
		InstructionOptimizer();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m);

	private:
		bool run();

	private:
		llvm::Module* _module = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
