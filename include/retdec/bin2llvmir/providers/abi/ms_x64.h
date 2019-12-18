/**
 * @file include/retdec/bin2llvmir/providers/abi/ms_x64.h
 * @brief ABI information for x86_64.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_MS_64_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_MS_64_H

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class AbiMS_X64 : public Abi
{
	// Ctors, dtors.
	//
	public:
		AbiMS_X64(llvm::Module* m, Config* c);

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
