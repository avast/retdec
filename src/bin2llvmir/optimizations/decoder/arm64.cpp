/**
* @file src/bin2llvmir/optimizations/decoder/arm64.cpp
* @brief Decoding methods specific to ARM64 architecture.
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

bool insnWrittesPcArm64(csh& ce, cs_insn* insn)
{
	//auto& arm64 = insn->detail->arm64;

	return insn->id == ARM64_INS_BL;

	// TODO: Arm64 doesn't allow PC to be an explicit operand
	// Create list of instructions that modify PC?

	/*
	// Implicit write.
	//
	if (cs_reg_write(ce, insn, ARM64_REG_PC))
	{
		return true;
	}

	// Explicit write.
	//
	for (std::size_t i = 0; i < arm64.op_count; ++i)
	{
		auto& op = arm64.operands[i];
		if (op.type == ARM64_OP_REG
				&& op.reg == ARM64_REG_PC
				&& op.access == CS_AC_WRITE)
		{
			return true;
		}
	}

	return false;
	*/
}

std::size_t Decoder::decodeJumpTargetDryRun_arm64(
		const JumpTarget& jt,
		ByteData bytes,
		bool strict)
{
	std::size_t decodedSzArm64 = 0;
	auto skipArm64 = decodeJumpTargetDryRun_arm64(
			jt,
			bytes,
			CS_MODE_ARM,
			decodedSzArm64,
			strict);

	std::size_t decodedSzThumb = 0;
	auto skipThumb = decodeJumpTargetDryRun_arm64(
			jt,
			bytes,
			CS_MODE_THUMB,
			decodedSzThumb,
			strict);

	// ARM64 ok.
	//
	if (skipArm64 == 0 && skipThumb)
	{
		jt.setMode(CS_MODE_ARM);
		return skipArm64;
	}
	// THUMB ok.
	//
	else if (skipArm64 && skipThumb == 0)
	{
		jt.setMode(CS_MODE_THUMB);
		return skipThumb;
	}
	// Both OK.
	//
	else if (skipArm64 == 0 && skipThumb == 0)
	{
		// Prefer ARM64.
		jt.setMode(CS_MODE_ARM);
		return 0;
	}
	// Both bad.
	//
	else
	{
		return skipArm64 < skipThumb ? skipArm64 : skipThumb;
	}
}

bool looksLikeArm64FunctionStart(cs_insn* insn)
{
	// Create stack frame 'stp x29, x30, [sp, -48]!'
	return insn->id == ARM64_INS_STP;
}

std::size_t Decoder::decodeJumpTargetDryRun_arm64(
		const JumpTarget& jt,
		ByteData bytes,
		cs_mode mode,
		std::size_t &decodedSz,
		bool strict)
{

	auto basicMode = _c2l->getBasicMode();
	if (mode != basicMode) _c2l->modifyBasicMode(mode);

	static csh ce = _c2l->getCapstoneEngine();

	decodedSz = 0;
	uint64_t addr = jt.getAddress();
	std::size_t nops = 0;
	bool first = true;
	while (cs_disasm_iter(ce, &bytes.first, &bytes.second, &addr, _dryCsInsn))
	{
		decodedSz += _dryCsInsn->size;

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
			if (mode != basicMode) _c2l->modifyBasicMode(basicMode);
			return nops;
		}

		if (_c2l->isControlFlowInstruction(*_dryCsInsn)
				|| insnWrittesPcArm64(ce, _dryCsInsn))
		{
			if (mode != basicMode) _c2l->modifyBasicMode(basicMode);
			return false;
		}

		first = false;
	}

	if (nops > 0)
	{
		if (mode != basicMode) _c2l->modifyBasicMode(basicMode);
		return nops;
	}

	// There is a BB right after, that is not a function start.
	//
	if (getBasicBlockAtAddress(addr) && getFunctionAtAddress(addr) == nullptr)
	{
		if (mode != basicMode) _c2l->modifyBasicMode(basicMode);
		return false;
	}

	if (mode != basicMode) _c2l->modifyBasicMode(basicMode);
	return true;
}

/**
 * Recognize some ARM64-specific patterns.
 */
void Decoder::patternsPseudoCall_arm64(llvm::CallInst*& call, AsmInstruction& ai)
{
	// TODO: We could detect this using architecture-agnostic approach by using
	// ABI info on LR reg.
	//
	// 113A0 0F E0 A0 E1    MOV LR, PC   // PC = current insn + 2*insn_size
	// 113A4 03 F0 A0 E1    MOV PC, R3   // branch -> call
	// 113A8 00 20 94 E5    LDR R2, [R4] // next insn = return point
	//
	// Check that both instructions have the same cond code:
	// 112E8 0F E0 A0 11    MOVNE LR, PC
	// 112EC 03 F0 A0 11    MOVNE PC, R3
	//
	/*
	if (_c2l->isBranchFunctionCall(call))
	{
		AsmInstruction prev = ai.getPrev();
		if (prev.isInvalid())
		{
			return;
		}
		auto* insn = ai.getCapstoneInsn();
		auto& arm64 = insn->detail->arm64;
		auto* pInsn = prev.getCapstoneInsn();
		auto& pArm64 = pInsn->detail->arm64;

		if (pInsn->id == ARM64_INS_MOV
				&& arm64.cc == pArm64.cc
				&& pArm64.op_count == 2
				&& pArm64.operands[0].type == ARM64_OP_REG
				&& pArm64.operands[0].reg == ARM64_REG_LR
				&& pArm64.operands[1].type == ARM64_OP_REG
				&& pArm64.operands[1].reg == ARM64_REG_PC)
		{
			// Replace pseudo branch with pseudo call.
			auto* nc = CallInst::Create(
					_c2l->getCallFunction(),
					{call->getArgOperand(0)},
					"",
					call);
			call->eraseFromParent();
			call = nc;
		}
	}
	*/
}

} // namespace bin2llvmir
} // namespace retdec
