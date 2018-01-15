/**
* @file src/bin2llvmir/optimizations/control_flow/arm.cpp
* @brief Reconstruct control flow -- ARM specific module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/control_flow/control_flow.h"
#include "retdec/bin2llvmir/utils/type.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool ControlFlow::runArm()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		changed |= runArmFunction(&f);
	}
	return changed;
}

bool ControlFlow::runArmFunction(llvm::Function* f)
{
	bool changed = false;

	auto ai = AsmInstruction(f);
	for (; ai.isValid(); ai = ai.getNext())
	{
		if (runArmReturn(ai))
		{
			changed = true;
			continue;
		}
		else if (runArmCall(ai))
		{
			changed = true;
			continue;
		}
	}

	return changed;
}

bool ControlFlow::runArmReturn(AsmInstruction& ai)
{
	// Typically function looks like this:
	// STMFD SP!, {R4,R11,LR}
	//     R4  -> stack_var -12
	//     R11 -> stack_var -8
	//     LR  -> stack_var -4
	// LDMFD SP!, {R4,R11,PC}
	//     stack_var -12 -> R4
	//     stack_var -8  -> R11
	//     stack_var -4  -> PC  -> jump -> __pseudo_br(stack_var -4)
	// The problem is how to know that __pseudo_br() jumps to the value
	// originally stored in LR (link register) -> it is return.
	// Here, we do not have stacks at the moment of control flow and it does
	// not run again later.
	// Solutions:
	// 1. Run control flow and stack several times -> problem = fixing.
	// What if 1. stack pass turns something into stack, but then cfg is
	// updated and in 2. stack pass, it is no longer possible to compute
	// the original stack offset.
	// 2. Try to do this without a stack analysis. Find STMFD, check if it
	// stores LR and where. Find LDMFD, check if it jumps and with what value.
	// Is it the same as where LR was stored? Either only position in
	// STMFD/LDMFD (easier), or stack offset (harder -- light stack analysis).
	// Problem = what if body is more complicated -- multiple STMFD/LDMFD.
	// 3. TODO: right now, we just consider every LDMFD that jumps to be
	// return.
	//
	if (ai.getCapstoneInsn()->id == ARM_INS_POP || ai.getCapstoneInsn()->id == ARM_INS_LDM)
	{
		// LDMFD   SP!, {R3-R9,PC}
		// If LDMFD writes in PC, in our semantics, it jumps using br function call.
		// As was described, right now we are not sure if written value is in
		// fact LR (return), or not (jump/call).
		//
		for (auto& i : ai)
		{
			if (auto* c = _config->isLlvmBranchPseudoFunctionCall(&i))
			{
				_toReturn.insert({ai, c});
				return true;
			}
		}
	}

	for (auto& i : ai)
	{
		auto* c = _config->isLlvmBranchPseudoFunctionCall(&i);
		if (c == nullptr)
		{
			continue;
		}

		auto* l = dyn_cast<LoadInst>(c->getArgOperand(0));
		if (l && l->getPointerOperand() == _config->getLlvmRegister("lr"))
		{
			_toReturn.insert({ai, c});
			return true;
		}
		// On THUMB, LR value may be aligned like this:
		//	%u3_859e = load i32, i32* @LR
		//	%_l_859e = add i32 -2, 0
		//	%u4_859e = and i32 %u3_859e, %_l_859e
		//	call void @__pseudo_br(i32 %u4_859e)
		// TODO: maybe make it more general -- any Br function working with
		// LR, not just this one pattern.
		//
		else if (auto* add = dyn_cast<BinaryOperator>(c->getArgOperand(0)))
		{
			auto* l0 = dyn_cast<LoadInst>(add->getOperand(0));
			auto* l1 = dyn_cast<LoadInst>(add->getOperand(1));
			auto* lr = _config->getLlvmRegister("lr");

			if ((isa<ConstantInt>(add->getOperand(0))
					&& l1 && l1->getPointerOperand() == lr)
					|| (isa<ConstantInt>(add->getOperand(1))
							&& l0 && l0->getPointerOperand() == lr))
			{
				_toReturn.insert({ai, c});
				return true;
			}
		}
	}

	if (_RDA.wasRun())
	{
		if (ai.getAddress() == 0x8670) // TODO: wtf hardcoded?
		{
			for (auto& i : ai)
			{
				auto* c = _config->isLlvmReturnPseudoFunctionCall(&i);
				if (c == nullptr)
				{
					continue;
				}

				SymbolicTree root(_RDA, c->getArgOperand(0));
				SymbolicTree* st = &root;
				while (st)
				{
					if (auto* l = dyn_cast<LoadInst>(st->value))
					{
						if (l->getPointerOperand() == _config->getLlvmRegister("lr"))
						{
							_toReturn.insert({ai, c});
							return true;
						}
					}

					st = st->ops.size() == 1 ? &st->ops[0] : nullptr;
				}
			}
		}
	}

	return false;
}

bool ControlFlow::runArmCall(AsmInstruction& ai)
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
		retdec::utils::Address target(ci->getZExtValue());

		// TODO: see align comment up
		// THUMB -> ARM (4 align)
		if (ai.getCapstoneInsn()->id == ARM_INS_BLX
// is THUMB insn? Better/safer would be to check insn's group.
				&& ai.getCapstoneInsn()->size == 2
				&& target % 4 != 0)
		{
			target = (target >> 2) << 2;
		}

		auto* ccf = _config->getLlvmFunction(target);
		// .plt:00008404 j_printf
		// .plt:00008404                 BX      PC
		// .plt:00008408 ; int printf(const char *format, ...
		//
		if (ccf == nullptr)
		{
			auto tt = target + 4;
			ccf = _config->getLlvmFunction(tt);
			if (ccf)
			{
				target = tt;
			}
		}

		_toCall.insert({c, target});
		return true;
	}

	//
	//
	cs_insn* aiC = ai.getCapstoneInsn();
	cs_arm* aiM = &aiC->detail->arm;
	Address imm;
	if (aiC->id == ARM_INS_LDR
			&& aiM->op_count == 2
			&& aiM->operands[0].type == ARM_OP_REG
			&& aiM->operands[0].reg >= ARM_REG_R0
			&& aiM->operands[0].reg <= ARM_REG_R12
			&& aiM->operands[1].type == ARM_OP_MEM
			&& aiM->operands[1].shift.type == ARM_SFT_INVALID
			&& aiM->operands[1].mem.base == ARM_REG_PC
			&& aiM->operands[1].mem.index == ARM_REG_INVALID
			&& aiM->operands[1].mem.lshift == 0
			&& aiM->operands[1].mem.scale == 1)
	{
		unsigned pcOff = ai.isThumb() ? 4 : 8;
		Address addr = ai.getAddress() + pcOff + aiM->operands[1].mem.disp;
		if (auto* ci = _image->getConstantDefault(addr))
		{
			imm = ci->getZExtValue();
		}
	}
	AsmInstruction tai(_module, imm);
	if (tai.isValid() && tai.getPrev().isValid())
	{
		cs_insn* taiC = tai.getCapstoneInsn();
		// TODO: Looks like ARM function start.
		if (taiC->id == ARM_INS_PUSH) // maybe || id == ARM_INS_STMDB as well.
		{
			_toFunctions.insert(tai);
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
