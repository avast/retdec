/**
* @file src/bin2llvmir/optimizations/decoder/ir_modifications.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

llvm::CallInst* Decoder::transformToCall(
		llvm::CallInst* pseudo,
		llvm::Function* callee)
{
	auto* c = CallInst::Create(callee);
	c->insertAfter(pseudo);

	if (auto* retObj = getCallReturnObject())
	{
		auto* cc = cast<Instruction>(
				IrModifier::convertValueToTypeAfter(c, retObj->getValueType(), c));
		auto* s = new StoreInst(cc, retObj);
		s->insertAfter(cc);
	}

	return c;
}

llvm::CallInst* Decoder::transformToCondCall(
		llvm::CallInst* pseudo,
		llvm::Value* cond,
		llvm::Function* callee,
		llvm::BasicBlock* falseBb)
{
	auto* oldBb = pseudo->getParent();
	auto* newBb = oldBb->splitBasicBlock(pseudo);
	// We do NOT want to name or give address to this block.

	auto* oldTerm = oldBb->getTerminator();
	BranchInst::Create(newBb, falseBb, cond, oldTerm);
	oldTerm->eraseFromParent();

	auto* newTerm = newBb->getTerminator();
	BranchInst::Create(falseBb, newTerm);
	newTerm->eraseFromParent();

	auto* c = CallInst::Create(callee);
	c->insertAfter(pseudo);

	return c;
}

llvm::ReturnInst* Decoder::transformToReturn(llvm::CallInst* pseudo)
{
	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* r = ReturnInst::Create(
			pseudo->getModule()->getContext(),
			UndefValue::get(pseudo->getFunction()->getReturnType()),
			term);
	term->eraseFromParent();

	return r;
}

llvm::BranchInst* Decoder::transformToBranch(
		llvm::CallInst* pseudo,
		llvm::BasicBlock* branchee)
{
	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* br = BranchInst::Create(branchee, term);
	term->eraseFromParent();

	return br;
}

llvm::BranchInst* Decoder::transformToCondBranch(
		llvm::CallInst* pseudo,
		llvm::Value* cond,
		llvm::BasicBlock* trueBb,
		llvm::BasicBlock* falseBb)
{
	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* br = BranchInst::Create(trueBb, falseBb, cond, term);
	term->eraseFromParent();

	return br;
}

llvm::SwitchInst* Decoder::transformToSwitch(
		llvm::CallInst* pseudo,
		llvm::Value* val,
		llvm::BasicBlock* defaultBb,
		const std::vector<llvm::BasicBlock*>& cases)
{
	unsigned numCases = 0;
	for (auto* c : cases)
	{
		if (c != defaultBb)
		{
			++numCases;
		}
	}

	// If we do not do this, this can happen:
	// "Instruction does not dominate all uses"
	auto* insn = dyn_cast<Instruction>(val);
	if (insn && insn->getType())
	{
		auto* gv = new GlobalVariable(
				*insn->getModule(),
				insn->getType(),
				false,
				GlobalValue::ExternalLinkage,
				nullptr);
		auto* s = new StoreInst(insn, gv);
		s->insertAfter(insn);

		val = new LoadInst(gv, "", pseudo);
	}

	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* intType = cast<IntegerType>(val->getType());
	auto* sw = SwitchInst::Create(val, defaultBb, numCases, term);
	unsigned cntr = 0;
	for (auto& c : cases)
	{
		if (c != defaultBb)
		{
			sw->addCase(ConstantInt::get(intType, cntr), c);
		}
		++cntr;
	}
	term->eraseFromParent();

	return sw;
}

/**
 * TODO: This will be replaced by a proper ABI provider.
 */
llvm::GlobalVariable* Decoder::getCallReturnObject()
{
	if (_config->getConfig().architecture.isX86_32())
	{
		return _module->getNamedGlobal("eax");
	}
	else if (_config->getConfig().architecture.isX86_64())
	{
		return _module->getNamedGlobal("rax");
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		return _config->getLlvmRegister("v0");
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		return _config->getLlvmRegister("r3");
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		return _config->getLlvmRegister("r0");
	}

	assert(false);
	return nullptr;
}

/**
 * Primary: try to create function for \p addr target and fill \p tFnc with
 * the result. If successful, \p tBb is also filled.
 * Secondary: if function not created, try to create BB for \p addr target and
 * fill \p tBb with the result.
 */
void Decoder::getOrCreateCallTarget(
		utils::Address addr,
		llvm::Function*& tFnc,
		llvm::BasicBlock*& tBb)
{
	tBb = nullptr;
	tFnc = nullptr;

	if (auto* f = getFunctionAtAddress(addr))
	{
		tFnc = f;
		tBb = tFnc->empty() ? nullptr : &tFnc->front();
		LOG << "\t\t\t\t" << "F: getFunctionAtAddress() @ " << addr << std::endl;
	}
	else if (auto* f = splitFunctionOn(addr))
	{
		tFnc = f;
		tBb = tFnc->empty() ? nullptr : &tFnc->front();
		LOG << "\t\t\t\t" << "F: splitFunctionOn() @ " << addr << std::endl;
	}
	else if (auto* bb = getBasicBlockAtAddress(addr))
	{
		tBb = bb;
		LOG << "\t\t\t\t" << "F: getBasicBlockAtAddress() @ " << addr << std::endl;
	}
	else if (getBasicBlockContainingAddress(addr))
	{
		// Nothing - we are not splitting BBs here.
		LOG << "\t\t\t\t" << "F: getBasicBlockContainingAddress() @ "
				<< addr << std::endl;
	}
	else if (getFunctionContainingAddress(addr))
	{
		auto* bb = getBasicBlockBeforeAddress(addr);
		assert(bb);
		tBb = createBasicBlock(addr, bb->getParent(), bb);
		LOG << "\t\t\t\t" << "F: getFunctionContainingAddress() @ "
				<< addr << std::endl;
	}
	else
	{
		tFnc = createFunction(addr);
		tBb = tFnc && !tFnc->empty() ? &tFnc->front() : nullptr;
		LOG << "\t\t\t\t" << "F: createFunction() @ "
				<< addr << std::endl;
	}
}

/**
 *
 */
void Decoder::getOrCreateBranchTarget(
		utils::Address addr,
		llvm::BasicBlock*& tBb,
		llvm::Function*& tFnc,
		llvm::Instruction* from)
{
	tBb = nullptr;
	tFnc = nullptr;

	auto* fromFnc = from->getFunction();

	if (auto* bb = getBasicBlockAtAddress(addr))
	{
		tBb = bb;
		LOG << "\t\t\t\t" << "B: getBasicBlockAtAddress() @ " << addr << std::endl;
	}
	else if (getBasicBlockContainingAddress(addr))
	{
		auto ai = AsmInstruction(_module, addr);
		if (ai.isInvalid())
		{
			// Target in existing block, but not at existing instruction.
			// Something is wrong, nothing we can do.
			LOG << "\t\t\t\t" << "B: invalid ASM @ " << addr << std::endl;
			return;
		}
		else if (ai.getFunction() == fromFnc)
		{
			tBb = ai.makeStart();
			addBasicBlock(addr, tBb);
			LOG << "\t\t\t\t" << "B: addBasicBlock @ " << addr << std::endl;
		}
		else
		{
			// Target at existing instruction, but in different function.
			// Do not split existing block in other functions here.
			LOG << "\t\t\t\t" << "B: ASM in diff fnc @ " << addr << std::endl;
			return;
		}
	}
	// Function without BBs (e.g. import declarations).
	else if (auto* targetFnc = getFunctionAtAddress(addr))
	{
		tFnc = targetFnc;
		LOG << "\t\t\t\t" << "B: getFunctionAtAddress() @ " << addr << std::endl;
	}
	else if (auto* bb = getBasicBlockBeforeAddress(addr))
	{
		tBb = createBasicBlock(addr, bb->getParent(), bb);
		LOG << "\t\t\t\t" << "B: getBasicBlockBeforeAddress() @ " << addr << std::endl;
	}
	else
	{
		tFnc = createFunction(addr);
		tBb = tFnc && !tFnc->empty() ? &tFnc->front() : nullptr;
		LOG << "\t\t\t\t" << "B: default @ " << addr << std::endl;
	}

	if (tBb && tBb->getPrevNode() == nullptr)
	{
		tFnc = tBb->getParent();
	}

	if (tBb && tBb->getParent() == fromFnc)
	{
		return;
	}
	if (tFnc)
	{
		return;
	}

	LOG << "\t\t\t\t" << "B: splitFunctionOn @ " << addr << std::endl;
	tFnc = splitFunctionOn(addr);
	tBb = tFnc && !tFnc->empty() ? &tFnc->front() : tBb;
}

/**
 * \return \c True if it is allowed to split function on basic block \p bb.
 */
bool Decoder::canSplitFunctionOn(llvm::BasicBlock* bb)
{
	for (auto* u : bb->users())
	{
		// All users must be unconditional branch instructions.
		//
		auto* br = dyn_cast<BranchInst>(u);
		if (br == nullptr || br->isConditional())
		{
			LOG << "\t\t\t\t\t\t" << "!CAN : user not uncond for "
					<< llvmObjToString(u)
					<< ", user = " << llvmObjToString(br) << std::endl;
			return false;
		}

		// Branch can not come from istruction right before basic block.
		// This expects that such branches were created
		// TODO: if
		//
		AsmInstruction brAsm(br);
		AsmInstruction bbAsm(bb);
		if (brAsm.getEndAddress() == bbAsm.getAddress())
		{
			LOG << "\t\t\t\t\t\t" << "branch from ASM insn right before: "
					<< brAsm.getAddress() << " -> " << bbAsm.getAddress()
					<< std::endl;
			return false;
		}

		// BB must be true branch in all users.
		//
//		if (br->getSuccessor(0) != bb)
//		{
//			return false;
//		}
	}

	return true;
}

/**
 * \return \c True if it is allowed to split function on basic block \p bb.
 *
 * TODO:
 * The problem here is, that function may became unsplittable after it was
 * split. What then? Merge them back together and transform calls to JUMP_OUTs?
 * Or defer splits/calls/etc only after basic decoding of all functions is done?
 * E.g.
 * fnc1():
 *     ...
 *     b lab_in_2
 *     ...
 *
 * fnc2(): (nothing decoded yet)
 *     ...
 *     // should not be split here, but it can, because flow from fnc2()
 *     // start does not exist yet.
 *     lab_in_2:
 *     ...
 *     fnc2 end
 */
bool Decoder::canSplitFunctionOn(
		utils::Address addr,
		llvm::BasicBlock* splitBb,
		std::set<llvm::BasicBlock*>& newFncStarts)
{
	newFncStarts.insert(splitBb);

	auto* f = splitBb->getParent();
	auto fAddr = getFunctionAddress(f);

	auto fSzIt = _fnc2sz.find(f);
	if (fSzIt != _fnc2sz.end())
	{
		if (fAddr <= addr && addr < (fAddr+fSzIt->second))
		{
			LOG << "\t\t\t\t\t" << "!CAN S: addr cond @ " << addr << std::endl;
			return false;
		}
	}

	std::set<Address> fncStarts;
	fncStarts.insert(fAddr);
	fncStarts.insert(addr);

	LOG << "\t\t\t\t\t" << "CAN S: split @ " << fAddr << std::endl;
	LOG << "\t\t\t\t\t" << "CAN S: split @ " << addr << std::endl;

	bool changed = true;
	while (changed)
	{
		changed = false;
		for (BasicBlock& b : *f)
		{
//			Address bAddr = getBasicBlockAddress(&b);
			Address bAddr;
			// TODO: shitty
			BasicBlock* bPrev = &b;
			while (bAddr.isUndefined() && bPrev)
			{
				bAddr = getBasicBlockAddress(bPrev);
				bPrev = bPrev->getPrevNode();
			}
			if (bAddr.isUndefined())
			{
				continue;
			}
			auto up = fncStarts.upper_bound(bAddr);
			--up;
			Address bFnc = *up;

			for (auto* p : predecessors(&b))
			{
//				Address pAddr = getBasicBlockAddress(p);
				Address pAddr;
				// TODO: shitty
				BasicBlock* pPrev = p;
				while (pAddr.isUndefined() && pPrev)
				{
					pAddr = getBasicBlockAddress(pPrev);
					pPrev = pPrev->getPrevNode();
				}
				if (pAddr.isUndefined())
				{
					continue;
				}
				auto up = fncStarts.upper_bound(pAddr);
				--up;
				Address pFnc = *up;

				if (bFnc != pFnc)
				{
					if (!canSplitFunctionOn(&b))
					{
						return false;
					}

					changed |= newFncStarts.insert(&b).second;
					changed |= fncStarts.insert(bAddr).second;

					LOG << "\t\t\t\t\t" << "CAN S: split @ " << bAddr << std::endl;
				}
			}
		}
	}

	return true;
}

/**
 * This can create new BB at \p addr even if it then cannot split function
 * on this new BB. Is this desirable behavior?
 */
llvm::Function* Decoder::splitFunctionOn(utils::Address addr)
{
	if (auto* bb = getBasicBlockAtAddress(addr))
	{
		LOG << "\t\t\t\t" << "S: splitFunctionOn @ " << addr << std::endl;
		return bb->getPrevNode()
				? splitFunctionOn(addr, bb)
				: bb->getParent();
	}
	// There is an instruction at address, but not BB -> do not split
	// existing blocks to create functions.
	//
	else if (auto ai = AsmInstruction(_module, addr))
	{
		if (ai.isInvalid())
		{
			LOG << "\t\t\t\t" << "S: invalid ASM @ " << addr << std::endl;
			return nullptr;
		}
		else
		{
			LOG << "\t\t\t\t" << "S: ASM @ " << addr << std::endl;
			return nullptr;
		}
	}
	else if (getFunctionContainingAddress(addr))
	{
		LOG << "\t\t\t\t" << "S: getFunctionContainingAddress() @ " << addr << std::endl;
		auto* before = getBasicBlockBeforeAddress(addr);
		assert(before);
		auto* newBb = createBasicBlock(addr, before->getParent(), before);
		return splitFunctionOn(addr, newBb);
	}
	else
	{
		LOG << "\t\t\t\t" << "S: createFunction() @ " << addr << std::endl;
		return createFunction(addr);
	}
}

llvm::Function* Decoder::splitFunctionOn(
		utils::Address addr,
		llvm::BasicBlock* splitOnBb)
{
	LOG << "\t\t\t\t" << "S: splitFunctionOn @ " << addr << " on "
			<< splitOnBb->getName().str() << std::endl;

	if (splitOnBb->getPrevNode() == nullptr)
	{
		LOG << "\t\t\t\t" << "S: BB first @ " << addr << std::endl;
		return splitOnBb->getParent();
	}
	std::set<BasicBlock*> newFncStarts;
	if (!canSplitFunctionOn(addr, splitOnBb, newFncStarts))
	{
		LOG << "\t\t\t\t" << "S: !canSplitFunctionOn() @ " << addr << std::endl;
		return nullptr;
	}

	llvm::Function* ret = nullptr;
	std::set<Function*> newFncs;
	for (auto* splitBb : newFncStarts)
	{
		Address splitAddr = getBasicBlockAddress(splitBb);

		LOG << "\t\t\t\t" << "S: splitting @ " << splitAddr << " on "
				<< splitBb->getName().str() << std::endl;

		std::string name = _names->getPreferredNameForAddress(splitAddr);
		if (name.empty())
		{
			name = names::generateFunctionName(splitAddr, _config->getConfig().isIda());
		}

		Function* oldFnc = splitBb->getParent();
		Function* newFnc = Function::Create(
				FunctionType::get(oldFnc->getReturnType(), false),
				oldFnc->getLinkage(),
				name);
		oldFnc->getParent()->getFunctionList().insertAfter(
				oldFnc->getIterator(),
				newFnc);

		addFunction(splitAddr, newFnc);

		newFnc->getBasicBlockList().splice(
				newFnc->begin(),
				oldFnc->getBasicBlockList(),
				splitBb->getIterator(),
				oldFnc->getBasicBlockList().end());

		newFncs.insert(oldFnc);
		newFncs.insert(newFnc);
		if (splitOnBb == splitBb)
		{
			ret = newFnc;
		}
	}
	assert(ret);

	for (Function* f : newFncs)
	for (BasicBlock& b : *f)
	{
		auto* br = dyn_cast<BranchInst>(b.getTerminator());
		if (br
				&& (br->getSuccessor(0)->getParent() != br->getFunction()
				|| br->getSuccessor(0)->getPrevNode() == nullptr))
		{
			auto* callee = br->getSuccessor(0)->getParent();
			auto* c = CallInst::Create(callee, "", br);
			if (auto* retObj = getCallReturnObject())
			{
				auto* cc = cast<Instruction>(
						IrModifier::convertValueToTypeAfter(c, retObj->getValueType(), c));
				auto* s = new StoreInst(cc, retObj);
				s->insertAfter(cc);
			}

			ReturnInst::Create(
					br->getModule()->getContext(),
					UndefValue::get(br->getFunction()->getReturnType()),
					br);
			br->eraseFromParent();
		}

		// Test.
		for (auto* s : successors(&b))
		{
			if (b.getParent() != s->getParent())
			{
				dumpModuleToFile(_module, _config->getOutputDirectory());
			}
			assert(b.getParent() == s->getParent());
		}
	}

	return ret;
}

} // namespace bin2llvmir
} // namespace retdec
