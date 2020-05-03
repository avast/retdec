/**
 * @file include/retdec/bin2llvmir/optimizations/writer_ll/writer_ll.h
 * @brief Generate the current LLVM IR.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_LL_WRITER_LL_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_LL_WRITER_LL_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class LlvmIrWriter : public llvm::ModulePass
{
	public:
		static char ID;
		LlvmIrWriter();
		virtual bool runOnModule(llvm::Module& M) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
