/**
 * @file include/retdec/bin2llvmir/optimizations/dump_module/dump_module.h
 * @brief An utility debug pass that dumps the module into a file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DUMP_MODULE_DUMP_MODULE_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DUMP_MODULE_DUMP_MODULE_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class DumpModule : public llvm::ModulePass
{
	public:
		static char ID;
		DumpModule();
		virtual bool runOnModule(llvm::Module& M) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
