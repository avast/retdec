/**
 * @file include/retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces_pass.h
 * @brief x86 address spaces optimization pass.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X86_ADDR_SPACES_X86_ADDR_SPACES_PASS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X86_ADDR_SPACES_X86_ADDR_SPACES_PASS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class X86AddressSpacesPass : public llvm::ModulePass
{
	public:
		static char ID;
		X86AddressSpacesPass();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Config* c);

	private:
		bool run();

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
