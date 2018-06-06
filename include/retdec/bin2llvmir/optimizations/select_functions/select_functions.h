/**
 * @file include/retdec/bin2llvmir/optimizations/select_functions/select_functions.h
 * @brief If ranges or functions are selected in config, remove bodies of all
 *        functions that are not selected.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SELECT_FUNCTIONS_SELECT_FUNCTIONS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SELECT_FUNCTIONS_SELECT_FUNCTIONS_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class SelectFunctions : public llvm::ModulePass
{
	public:
		static char ID;
		SelectFunctions();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c);

	private:
		bool run(llvm::Module& M);

	private:
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
