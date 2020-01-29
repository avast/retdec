/**
 * @file include/retdec/bin2llvmir/providers/abi/x64.h
 * @brief ABI information for x86_64.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_X64_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_X64_H

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class AbiX64 : public Abi
{
	// Ctors, dtors.
	//
	public:
		AbiX64(llvm::Module* m, Config* c);

	// Registers.
	//
	public:
		virtual bool isGeneralPurposeRegister(const llvm::Value* val) const override;

	// Instructions.
	//
	public:
		virtual bool isNopInstruction(cs_insn* insn) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
