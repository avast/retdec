/**
* @file src/bin2llvmir/optimizations/control_flow/mips.cpp
* @brief Reconstruct control flow -- MIPS specific module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/control_flow/control_flow.h"
#include "retdec/bin2llvmir/utils/type.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool ControlFlow::runMips()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		changed |= runMipsFunction(&f);
	}
	return changed;
}

bool ControlFlow::runMipsFunction(llvm::Function* f)
{
	bool changed = false;

	AsmInstruction ai(f);
	for (; ai.isValid(); ai = ai.getNext())
	{
		if (runMipsReturn(ai))
		{
			changed = true;
			continue;
		}
		else if (runMipsCall(ai))
		{
			changed = true;
			continue;
		}
	}

	return changed;
}

bool ControlFlow::runMipsReturn(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		auto* c = _config->isLlvmReturnPseudoFunctionCall(&i);
		if (c == nullptr)
		{
			c = _config->isLlvmBranchPseudoFunctionCall(&i);
		}

		if (c)
		{
			auto* l = dyn_cast<LoadInst>(c->getArgOperand(0));
			if (l && l->getPointerOperand() == _config->getLlvmRegister("ra"))
			{
				_toReturn.insert({ai, c});
				return true;
			}
		}
	}

	return false;
}

bool ControlFlow::runMipsCall(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		auto* c = _config->isLlvmCallPseudoFunctionCall(&i);
		if (c == nullptr)
		{
			continue;
		}

		auto* ci = dyn_cast<ConstantInt>(c->getArgOperand(0));
		if (ci == nullptr)
		{
			// TODO -- call variable
			// 1.) if RDA available, try to compute it.
			// 2.) if not computed, transform to call of variable.
			continue;
		}

		_toCall.insert({c, ci->getZExtValue()});
		return true;
	}

	return false;
}

/**
 * busybox:
 *   LOAD:0042FA10 _fprintf:
 *   LOAD:0042FA10                 lw      $t9, dword_448F70
 *   LOAD:0042FA14                 move    $t7, $ra
 *   LOAD:0042FA18                 jalr    $t9
 *   LOAD:0042FA1C                 li      $t8, 0x8F
 *   LOAD:0042FA1C  # End of function _fprintf
 */
bool ControlFlow::runMipsDynamicStubPatter()
{
	bool changed = false;
	for (auto& fnc : *_module)
	{
		AsmInstruction ai1(&fnc);
		AsmInstruction ai2 = ai1.getNext();
		AsmInstruction ai3 = ai2.getNext();
		AsmInstruction ai4 = ai3.getNext();

		if (!(ai1 && ai2 && ai3 && ai4))
		{
			continue;
		}

		if (!(ai1.getCapstoneInsn()->id == MIPS_INS_LW
				&& ai2.getCapstoneInsn()->id == MIPS_INS_MOVE
				&& ai3.getCapstoneInsn()->id == MIPS_INS_JALR
				&& ai4.getCapstoneInsn()->id == MIPS_INS_ADDIU))
		{
			continue;
		}

		auto* lti = LtiProvider::getLti(_module);
		if (lti == nullptr)
		{
			continue;
		}
		if (!(lti->hasLtiFunction(fnc.getName())
				|| lti->hasLtiFunction(retdec::utils::removeLeadingCharacter(fnc.getName(), '_'))))
		{
			continue;
		}

		auto* cf = _config->getConfigFunction(&fnc);
		if (cf == nullptr)
		{
			continue;
		}

		fnc.deleteBody();
		cf->setIsDynamicallyLinked();
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
