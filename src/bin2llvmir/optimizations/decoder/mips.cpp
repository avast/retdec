/**
* @file src/bin2llvmir/optimizations/decoder/mips.cpp
* @brief Decoding methods specific to MIPS architecture.
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

/**
 * Patterns of branch instructions that does not make sense and should not
 * be accepted.
 */
bool isBadBranch(FileImage* img, cs_insn* br)
{
	auto& mips = br->detail->mips;

	// jr $zero
	//
	if (br->id == MIPS_INS_JR
			&& mips.op_count == 1
			&& mips.operands[0].type == MIPS_OP_REG
			&& mips.operands[0].reg == MIPS_REG_ZERO)
	{
		return true;
	}
	// j <bad_value>
	//
	if ((br->id == MIPS_INS_J || br->id == MIPS_INS_B)
			&& mips.op_count == 1
			&& mips.operands[0].type == MIPS_OP_IMM
			&& !img->getImage()->hasDataInitializedOnAddress(mips.operands[0].imm))
	{
		return true;
	}

	return false;
}

bool Decoder::disasm_mips(
		csh ce,
		cs_mode m,
		ByteData& bytes,
		uint64_t& a,
		cs_insn* i)
{
	bool ret = cs_disasm_iter(ce, &bytes.first, &bytes.second, &a, i);

	if (ret == false && (m & CS_MODE_MIPS32))
	{
		_c2l->modifyBasicMode(CS_MODE_MIPS64);
		ret = cs_disasm_iter(ce, &bytes.first, &bytes.second, &a, i);
		_c2l->modifyBasicMode(CS_MODE_MIPS32);
	}

	return ret;
}

std::size_t Decoder::decodeJumpTargetDryRun_mips(
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
	unsigned counter = 0;
	unsigned cfChangePos = 0;
	while (disasm_mips(ce, _c2l->getBasicMode(), bytes, addr, _dryCsInsn))
	{
		++counter;

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

		if (_c2l->isReturnInstruction(*_dryCsInsn))
		{
			return false;
		}
		if (_c2l->isBranchInstruction(*_dryCsInsn)
				&& !isBadBranch(_image, _dryCsInsn))
		{
			return false;
		}

		if (_c2l->isReturnInstruction(*_dryCsInsn)
				|| _c2l->isBranchInstruction(*_dryCsInsn)
				|| _c2l->isCondBranchInstruction(*_dryCsInsn)
				|| _c2l->isCallInstruction(*_dryCsInsn))
		{
			cfChangePos = counter;
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

	// We decoded exactly tho whole range, there is at least some good number
	// of instructions, and block ended with control flow change (+possible
	// delay slot).
	//
	if (bytes.second == 0
			&& counter >= 8
			&& (cfChangePos == counter || cfChangePos+1 == counter))
	{
		return false;
	}

	return true;
}

void Decoder::initializeGpReg_mips()
{
	if (!_config->getConfig().architecture.isPic32())
	{
		return;
	}

	if (auto* gp = _module->getNamedGlobal("gp"))
	{
		Address lastAddr;
		StoreInst* lastStore = nullptr;

		for (auto* u : gp->users())
		{
			if (auto* s = dyn_cast<StoreInst>(u))
			{
				auto addr = AsmInstruction::getInstructionAddress(s);
				if (lastAddr.isUndefined() || addr > lastAddr)
				{
					lastAddr = addr;
					lastStore = s;
				}
			}
		}

		if (lastStore)
		{
			SymbolicTree root(_RDA, lastStore->getValueOperand());
			root.simplifyNode();
			if (auto* ci = dyn_cast_or_null<ConstantInt>(root.value))
			{
				gp->setInitializer(ci);
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
