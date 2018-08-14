/**
 * @file src/bin2llvmir/providers/abi/arm.cpp
 * @brief ABI information for ARM.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/arm.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiArm::AbiArm(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.reserve(ARM_REG_ENDING);
	_id2regs.resize(ARM_REG_ENDING, nullptr);
	_regStackPointerId = ARM_REG_SP;

	// system calls
	_regSyscallId = ARM_REG_R7;
	_regSyscallReturn = ARM_REG_R0;
	_syscallRegs = {
			ARM_REG_R0,
			ARM_REG_R1,
			ARM_REG_R2,
			ARM_REG_R3,
			ARM_REG_R4,
			ARM_REG_R5};
}

AbiArm::~AbiArm()
{

}

bool AbiArm::isGeneralPurposeRegister(const llvm::Value* val)
{
	uint32_t rid = getRegisterId(val);
	return ARM_REG_R0 <= rid && rid <= ARM_REG_R12;
}

bool AbiArm::isNopInstruction(cs_insn* insn)
{
	// True NOP variants.
	//
	if (insn->id == ARM_INS_NOP)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
