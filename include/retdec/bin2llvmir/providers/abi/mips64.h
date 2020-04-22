/**
 * @file include/retdec/bin2llvmir/providers/abi/mips64.h
 * @brief ABI information for MIPS.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_MIPS64_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_MIPS64_H

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class AbiMips64 : public Abi
{
	// Ctors, dtors.
	//
	public:
		AbiMips64(llvm::Module* m, Config* c);

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
