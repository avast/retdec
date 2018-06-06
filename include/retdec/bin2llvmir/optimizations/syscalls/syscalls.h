/**
 * @file include/retdec/bin2llvmir/optimizations/syscalls/syscalls.h
 * @brief Implement syscall identification and fixing pass @c SyscallFixer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SYSCALLS_SYSCALLS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SYSCALLS_SYSCALLS_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/utils/debug.h"
const bool debug_enabled = false;

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
				Lti* lti,
				Abi* abi);

	private:
		bool run();
		bool transform(
				AsmInstruction ai,
				uint64_t code,
				const std::map<uint64_t, std::string>& codeMap);

		bool runArm();
		bool runArm_linux_32();
		bool runArm_linux_32(AsmInstruction ai);

		bool runMips();
		bool runMips_linux();
		bool runMips_linux(AsmInstruction ai);

		bool runX86();
		bool runX86_linux_32();
		bool runX86_linux_32(AsmInstruction ai);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		Lti* _lti = nullptr;
		Abi* _abi = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
