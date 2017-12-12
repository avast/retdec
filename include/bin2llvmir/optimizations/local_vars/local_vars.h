/**
* @file include/bin2llvmir/optimizations/local_vars/local_vars.h
* @brief Register localization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BIN2LLVMIR_OPTIMIZATIONS_LOCAL_VARS_LOCAL_VARS_H
#define BIN2LLVMIR_OPTIMIZATIONS_LOCAL_VARS_LOCAL_VARS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "bin2llvmir/analyses/reaching_definitions.h"
#include "bin2llvmir/providers/config.h"

namespace bin2llvmir {

class LocalVars : public llvm::ModulePass
{
	public:
		static char ID;
		LocalVars();
		virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
		virtual bool runOnModule(llvm::Module& M) override;

	private:
		Config* config = nullptr;
};

} // namespace bin2llvmir

#endif
