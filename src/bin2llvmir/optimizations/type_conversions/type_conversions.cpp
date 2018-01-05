/**
 * @file src/bin2llvmir/optimizations/type_conversions/type_conversions.cpp
 * @brief Removes unnecessary data type conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/PatternMatch.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/type_conversions/type_conversions.h"
#include "retdec/bin2llvmir/utils/defs.h"

using namespace retdec::llvm_support;
using namespace llvm;
using namespace PatternMatch;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

char TypeConversions::ID = 0;

static RegisterPass<TypeConversions> LLVMTestRegistered(
		"type-conversions",
		"Data type conversions optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

TypeConversions::TypeConversions() :
		ModulePass(ID),
		_module(nullptr)
{

}

bool TypeConversions::doInitialization(Module& M)
{
	_module = &M;
	return true;
}

bool TypeConversions::runOnModule(llvm::Module& M)
{
	bool overallChange = false;
	for (auto& F : M.getFunctionList())
	{
		overallChange |= runOnFunction(F);
	}
	return overallChange;
}

bool TypeConversions::runOnFunction(Function& F)
{
	bool overallChange = false;
	bool passChange = false;

	do
	{
		passChange = false;
		for (auto& bb : F)
		{
			auto it = bb.begin();
			while (it != bb.end())
			{
				// We need to move to the next before optimizing (potentially
				// removing) the current instruction. Otherwise, the iterator
				// would become invalid.
				//
				auto* inst = &(*it);
				++it;

				if (removePtrToIntToPtr(inst))
				{
					passChange = true;
				}
				else
				{
					passChange |= runInInstruction(inst);
				}

				overallChange |= passChange;
			}
		}
	}
	while (passChange);

	return overallChange;
}

bool TypeConversions::removePtrToIntToPtr(llvm::Instruction* instr)
{
	if (!(isa<IntToPtrInst>(instr) && isa<PtrToIntInst>(instr->getOperand(0))))
		return false;

	auto* p2i = dyn_cast<PtrToIntInst>(instr->getOperand(0));
	auto* bc = BitCastInst::CreatePointerCast(
			p2i->getOperand(0),
			instr->getType(),
			"",
			instr);
	instr->replaceAllUsesWith(bc);
	instr->eraseFromParent();
	if (p2i->getNumUses() == 0)
		p2i->eraseFromParent();
	return true;
}

bool TypeConversions::runInInstruction(Instruction* start)
{
	if (!start->isCast())
	{
		return false;
	}

	LOG << "|> " << llvmObjToString(start) << std::endl;

	Instruction* prev = start;
	unsigned cntr = 0;
	Instruction* lastGood = nullptr;

	while (prev && prev->isCast())
	{
		Value* castSrc = nullptr;
		if (prev->getNumOperands() > 0)
			castSrc = prev->getOperand(0);

		LOG << "\t|> " << llvmObjToString(prev) << std::endl;

		if (castSrc)
		{
			LOG << "\t\t|> " << llvmObjToString(castSrc) << std::endl;

			++cntr;
			if ( (start->getType()->isFloatingPointTy() &&
					castSrc->getType()->isFloatingPointTy()) ||
				 (start->getType()->isIntegerTy() &&
					castSrc->getType()->isIntegerTy()))
			{
				lastGood = dyn_cast<Instruction>(castSrc);
			}

			if (Argument* arg = dyn_cast<Argument>(castSrc))
			{
				if (arg->getType() == start->getType() && start->getNumUses())
				{
					LOG << "\t|> arg: " << llvmObjToString(arg) << std::endl;
					start->replaceAllUsesWith(arg);
					start->eraseFromParent();
					return true;
				}
			}

			else if (GlobalVariable* glob = dyn_cast<GlobalVariable>(castSrc))
			{
				if (glob->getType() == start->getType() && start->getNumUses())
				{
					LOG << "\t|> global: " << llvmObjToString(glob) << std::endl;
					start->replaceAllUsesWith(glob);
					start->eraseFromParent();
					return true;
				}
			}

			else if (Instruction* inst = dyn_cast<Instruction>(castSrc))
			{
				if (inst != start
						&& start->getNumUses()
						&& inst->getParent() == start->getParent()
						&& inst->getType() == start->getType())
				{
					LOG << "\t|> inst: " << llvmObjToString(inst) << std::endl;
					start->replaceAllUsesWith(inst);
					start->eraseFromParent();
					return true;
				}
			}

			if (prev->getOpcode() != Instruction::FPToSI
				&& prev->getOpcode() != Instruction::FPToUI
				&& prev->getOpcode() != Instruction::UIToFP
				&& prev->getOpcode() != Instruction::SIToFP)
			{
				LOG << "\t|> prev: " << llvmObjToString(castSrc) << std::endl;
				prev = dyn_cast<Instruction>(castSrc);
			}
			else
			{
				return replaceByShortcut(start, lastGood, cntr);
			}
		}
		else
		{
			return replaceByShortcut(start, lastGood, cntr);
		}
	}

	return replaceByShortcut(start, lastGood, cntr);
}

bool TypeConversions::replaceByShortcut(
		Instruction* start,
		Instruction* lastGood,
		unsigned cntr)
{
	LOG << "replaceByShortcut() : "
		<< llvmObjToString(start) << " -> "
		<< llvmObjToString(lastGood) << std::endl;

	if (lastGood
			&& start->getNumUses()
			&& lastGood->getParent() == start->getParent())
	{
		if (start->getType()->isFloatingPointTy()
				&& !lastGood->getType()->isFloatingPointTy())
		{
			return false; // should not happen
		}
		if (start->getType()->isIntegerTy()
				&& !lastGood->getType()->isIntegerTy())
		{
			return false; // should not happen
		}

		// General type (int/float) of start and lastGood should be the same.
		//
		if (lastGood->getOpcode() == Instruction::SIToFP)
		{
			Instruction *n = new SIToFPInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (lastGood->getOpcode() == Instruction::UIToFP)
		{
			Instruction *n = new UIToFPInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (lastGood->getOpcode() == Instruction::FPToSI)
		{
			Instruction *n = new FPToSIInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (lastGood->getOpcode() == Instruction::FPToUI)
		{
			Instruction *n = new FPToUIInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (cntr>1 && start->getType()->isFloatingPointTy())
		{
			Instruction *n = CastInst::CreateFPCast(
					lastGood,
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			// do not return true here
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
