/**
 * @file src/bin2llvmir/providers/abi/arm64.cpp
 * @brief ABI information for ARM64.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/arm64.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiArm64::AbiArm64(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.reserve(ARM64_REG_ENDING);
	_id2regs.resize(ARM64_REG_ENDING, nullptr);
	_regStackPointerId = ARM64_REG_SP;

	// system calls
	_regSyscallId = ARM64_REG_X8;
	_regSyscallReturn = ARM64_REG_X0;
	_syscallRegs = {
			ARM64_REG_X0,
			ARM64_REG_X1,
			ARM64_REG_X2,
			ARM64_REG_X3,
			ARM64_REG_X4,
			ARM64_REG_X5};

	_defcc = CallingConvention::ID::CC_ARM64;
}

bool AbiArm64::isGeneralPurposeRegister(const llvm::Value* val) const
{
	uint32_t rid = getRegisterId(val);
	return ARM64_REG_X0 <= rid && rid <= ARM64_REG_X30;
}

bool AbiArm64::isNopInstruction(cs_insn* insn)
{
	// True NOP variants.
	//
	if (insn->id == ARM64_INS_NOP)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
