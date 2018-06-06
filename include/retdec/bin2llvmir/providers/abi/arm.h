/**
 * @file include/retdec/bin2llvmir/providers/abi/arm.h
 * @brief ABI information for ARM.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_ARM_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_ARM_H

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class AbiArm : public Abi
{
	// Ctors, dtors.
	//
	public:
		AbiArm(llvm::Module* m, Config* c);
		virtual ~AbiArm();

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
