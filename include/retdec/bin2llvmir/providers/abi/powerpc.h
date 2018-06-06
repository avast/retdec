/**
 * @file include/retdec/bin2llvmir/providers/abi/powerpc.h
 * @brief ABI information for PowerPC.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_POWERPC_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_POWERPC_H

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class AbiPowerpc : public Abi
{
	// Ctors, dtors.
	//
	public:
		AbiPowerpc(llvm::Module* m, Config* c);
		virtual ~AbiPowerpc();

	// Registers.
	//
	public:
		virtual bool isGeneralPurposeRegister(const llvm::Value* val) override;

	// Instructions.
	//
	public:
		virtual bool isNopInstruction(cs_insn* insn) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
