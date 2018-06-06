/**
* @file src/bin2llvmir/optimizations/decoder/x86.cpp
* @brief Decoding methods specific to x86 architecture.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/capstone.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

std::size_t Decoder::decodeJumpTargetDryRun_x86(
		const JumpTarget& jt,
		ByteData bytes,
		bool strict)
{
	if (strict)
	{
		return true;
	}

	static csh ce = _c2l->getCapstoneEngine();

	uint64_t addr = jt.getAddress();
	std::size_t nops = 0;
	bool first = true;
	bool storeOneToEax = false;
	bool lastSyscall = false;
	std::size_t decodedSz = 0;
	while (cs_disasm_iter(ce, &bytes.first, &bytes.second, &addr, _dryCsInsn))
	{
		decodedSz += _dryCsInsn->size;
		auto& detail = _dryCsInsn->detail->x86;

		if (jt.getType() == JumpTarget::eType::LEFTOVER
				&& (first || nops > 0)
				&& _abi->isNopInstruction(_dryCsInsn))
		{
			nops += _dryCsInsn->size;
		}
		else if (jt.getType() == JumpTarget::eType::LEFTOVER
				&& nops > 0)
		{
			return nops;
		}

		if (_c2l->isReturnInstruction(*_dryCsInsn)
				|| _c2l->isBranchInstruction(*_dryCsInsn))
		{
			return false;
		}

		// TODO: not very strict - not checking that eax is not overwritten.
		if (_dryCsInsn->id == X86_INS_MOV
				&& detail.op_count == 2
				&& detail.operands[0].type == X86_OP_REG
				&& detail.operands[0].reg == X86_REG_EAX
				&& detail.operands[1].type == X86_OP_IMM
				&& detail.operands[1].imm == 1)
		{
			storeOneToEax = true;
		}
		if (_dryCsInsn->id == X86_INS_INT
				&& detail.op_count == 1
				&& detail.operands[0].type == X86_OP_IMM
				&& detail.operands[0].imm == 0x80)
		{
			if (storeOneToEax)
			{
				return false;
			}
			lastSyscall = true;
		}
		else if (_dryCsInsn->id == X86_INS_SYSCALL)
		{
			lastSyscall = true;
		}
		else
		{
			lastSyscall = false;
		}

		first = false;
	}

	if (nops > 0)
	{
		return nops;
	}

	if (lastSyscall && decodedSz >= 0x10)
	{
		return false;
	}

	// There is a BB right after, that is not a function start.
	//
	if (getBasicBlockAtAddress(addr) && getFunctionAtAddress(addr) == nullptr)
	{
		return false;
	}

	return true;
}

} // namespace bin2llvmir
} // namespace retdec
