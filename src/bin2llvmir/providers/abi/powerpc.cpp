/**
 * @file src/bin2llvmir/providers/abi/powerpc.cpp
 * @brief ABI information for PowerPC.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/powerpc.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiPowerpc::AbiPowerpc(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.reserve(PPC_REG_ENDING);
	_id2regs.resize(PPC_REG_ENDING, nullptr);
	_regStackPointerId = PPC_REG_R1;
}

AbiPowerpc::~AbiPowerpc()
{

}

bool AbiPowerpc::isGeneralPurposeRegister(const llvm::Value* val)
{
	uint32_t rid = getRegisterId(val);
	return PPC_REG_R0 <= rid && rid <= PPC_REG_R31;
}

bool AbiPowerpc::isNopInstruction(cs_insn* insn)
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
