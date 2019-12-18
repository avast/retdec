/**
 * @file src/bin2llvmir/providers/abi/x64.cpp
 * @brief ABI information for x86_64.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/x64.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiX64::AbiX64(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.reserve(X86_REG_ENDING);
	_id2regs.resize(X86_REG_ENDING, nullptr);
	_regStackPointerId = X86_REG_RSP;

	// system calls
	_regSyscallId = X86_REG_EAX;
	_regSyscallReturn = X86_REG_EAX;
	_syscallRegs = {
		X86_REG_RDI,
		X86_REG_RSI,
		X86_REG_RDX,
		X86_REG_R10,
		X86_REG_R8,
		X86_REG_R9};

	_defcc = CallingConvention::ID::CC_X64;
}

bool AbiX64::isGeneralPurposeRegister(const llvm::Value* val) const
{
	uint32_t rid = getRegisterId(val);
	return rid == X86_REG_RAX
			|| rid == X86_REG_RBX
			|| rid == X86_REG_RCX
			|| rid == X86_REG_RDX
			|| rid == X86_REG_RSP
			|| rid == X86_REG_RBP
			|| rid == X86_REG_RSI
			|| rid == X86_REG_RDI
			|| rid == X86_REG_R8
			|| rid == X86_REG_R9
			|| rid == X86_REG_R10
			|| rid == X86_REG_R11
			|| rid == X86_REG_R12
			|| rid == X86_REG_R13
			|| rid == X86_REG_R14
			|| rid == X86_REG_R15;
}

bool AbiX64::isNopInstruction(cs_insn* insn)
{
	cs_x86& insn86 = insn->detail->x86;

	// True NOP variants.
	//
	if (insn->id == X86_INS_NOP
			|| insn->id == X86_INS_FNOP
			|| insn->id == X86_INS_FDISI8087_NOP
			|| insn->id == X86_INS_FENI8087_NOP
			|| insn->id == X86_INS_INT3)
	{
		return true;
	}
	// e.g. lea esi, [esi]
	//
	else if (insn->id == X86_INS_LEA
			&& insn86.disp == 0
			&& insn86.op_count == 2
			&& insn86.operands[0].type == X86_OP_REG
			&& insn86.operands[1].type == X86_OP_MEM
			&& insn86.operands[1].mem.segment == X86_REG_INVALID
			&& insn86.operands[1].mem.index == X86_REG_INVALID
			&& insn86.operands[1].mem.scale == 1
			&& insn86.operands[1].mem.disp == 0
			&& insn86.operands[1].mem.base == insn86.operands[0].reg)
	{
		return true;
	}
	// e.g. mov esi. esi
	//
	else if (insn->id == X86_INS_MOV
			&& insn86.disp == 0
			&& insn86.op_count == 2
			&& insn86.operands[0].type == X86_OP_REG
			&& insn86.operands[1].type == X86_OP_REG
			&& insn86.operands[0].reg == insn86.operands[1].reg)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
