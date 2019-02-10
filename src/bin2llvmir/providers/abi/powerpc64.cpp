/**
 * @file src/bin2llvmir/providers/abi/powerpc64.cpp
 * @brief ABI information for PowerPC 64.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/powerpc64.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiPowerpc64::AbiPowerpc64(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.reserve(PPC_REG_ENDING);
	_id2regs.resize(PPC_REG_ENDING, nullptr);
	_regStackPointerId = PPC_REG_R1;
	_fpRegsAsParams = true;

	_paramRegs = {
		PPC_REG_R3,
		PPC_REG_R4,
		PPC_REG_R5,
		PPC_REG_R6,
		PPC_REG_R7,
		PPC_REG_R8,
		PPC_REG_R9,
		PPC_REG_R10};

	_paramFPRegs = {
		PPC_REG_F1,
		PPC_REG_F2,
		PPC_REG_F3,
		PPC_REG_F4,
		PPC_REG_F5,
		PPC_REG_F6,
		PPC_REG_F7,
		PPC_REG_F8,
		PPC_REG_F9,
		PPC_REG_F10,
		PPC_REG_F11};

	// TODO paramVectorRegs = 


	_regReturn = PPC_REG_R3;
	_regFPReturn = PPC_REG_R3;
}

AbiPowerpc64::~AbiPowerpc64()
{

}

bool AbiPowerpc64::isGeneralPurposeRegister(const llvm::Value* val)
{
	uint32_t rid = getRegisterId(val);
	return PPC_REG_R0 <= rid && rid <= PPC_REG_R31;
}

bool AbiPowerpc64::isNopInstruction(cs_insn* insn)
{
	// True NOP variants.
	//
	if (insn->id == PPC_INS_NOP
			|| insn->id == PPC_INS_XNOP)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
