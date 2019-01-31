/**
* @file include/retdec/bin2llvmir/optimizations/x87_fpu/x87_fpu.h
* @brief x87 FPU analysis - replace fpu stack operations with FPU registers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X87_FPU_X87_FPU_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X87_FPU_X87_FPU_H

#include <map>

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class X87FpuAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		X87FpuAnalysis();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				Abi* a);

	private:
		bool run();
		bool analyzeBb(
				retdec::utils::NonIterableSet<llvm::BasicBlock*>& seenBbs,
				std::map<llvm::Value*, int>& topVals,
				llvm::BasicBlock* bb,
				int topVal);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		llvm::GlobalVariable* top = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
