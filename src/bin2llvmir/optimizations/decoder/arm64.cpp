/**
* @file src/bin2llvmir/optimizations/decoder/arm64.cpp
* @brief Decoding methods specific to ARM64 architecture.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/capstone.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool insnWrittesPcArm64(csh& ce, cs_insn* insn)
{
	// Aarch64 reference manual states:
	// Software cannot write directly to the PC. It can only
	// be updated on a branch, exception entry or exception return.

	// Set of instructions that can modify PC
	const std::set<unsigned int> branch_instructions = {
		ARM64_INS_B,
		ARM64_INS_CBNZ,
		ARM64_INS_CBZ,
		ARM64_INS_TBNZ,
		ARM64_INS_TBZ,
		ARM64_INS_BL,
		ARM64_INS_BLR,
		ARM64_INS_BR,
		ARM64_INS_RET,
		ARM64_INS_ERET,
	};

	return (branch_instructions.count(insn->id) != 0);
}

bool looksLikeArm64FunctionStart(cs_insn* insn)
{
	// Create stack frame 'stp x29, x30, [sp, -48]!'
	return insn->id == ARM64_INS_STP;
}

std::size_t Decoder::decodeJumpTargetDryRun_arm64(
		const JumpTarget& jt,
		ByteData bytes,
		bool strict)
{

	if (strict)
	{
		return true;
	}

	csh ce = _c2l->getCapstoneEngine();

	uint64_t addr = jt.getAddress();
	std::size_t nops = 0;
	bool first = true;
	// bytes.first  -> Code
	// bytes.second -> Code size
	// addr         -> Address of first instruction
	while (cs_disasm_iter(ce, &bytes.first, &bytes.second, &addr, _dryCsInsn))
	{

		if (strict && first && !looksLikeArm64FunctionStart(_dryCsInsn))
		{
			return true;
		}

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

		if (_c2l->isControlFlowInstruction(*_dryCsInsn)
				|| insnWrittesPcArm64(ce, _dryCsInsn))
		{
			return false;
		}

		first = false;
	}

	if (nops > 0)
	{
		return nops;
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
