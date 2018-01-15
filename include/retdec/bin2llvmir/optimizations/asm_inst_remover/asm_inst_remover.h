/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.h
 * @brief Remove all special instructions used to map LLVM instructions to
 *        ASM instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_REMOVER_ASM_INST_REMOVER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_REMOVER_ASM_INST_REMOVER_H

#include <set>

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class AsmInstructionRemover : public llvm::ModulePass
{
	public:
		static char ID;
		AsmInstructionRemover();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c);

	private:
		bool run(llvm::Module& M);
		bool renameTempVariables(llvm::Module& M);

	private:
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
