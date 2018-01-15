/**
 * @file include/retdec/bin2llvmir/optimizations/syscalls/syscalls.h
 * @brief Implement syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SYSCALLS_SYSCALLS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SYSCALLS_SYSCALLS_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"

namespace retdec {
namespace bin2llvmir {

class AsmInstruction;

class SyscallFixer : public llvm::ModulePass
{
	public:
		static char ID;
		SyscallFixer();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(
				llvm::Module& M,
				Config* c,
				FileImage* img,
				Lti* lti);

	private:
		bool run();
		bool runMips();
		bool runArm();
		bool runX86();
		bool x86TransformToDummySyscall(AsmInstruction& ai);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		Lti* _lti = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
