/**
 * @file include/retdec/bin2llvmir/optimizations/writer_bc/writer_bc.h
 * @brief Generate the current bitcode.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_BC_WRITER_BC_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_BC_WRITER_BC_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class BitcodeWriter : public llvm::ModulePass
{
	public:
		static char ID;
		BitcodeWriter();
		virtual bool runOnModule(llvm::Module& M) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
