/**
* @file src/bin2llvmir/analyses/reaching_definitions.cpp
* @brief Reaching definitions analysis builds UD and DU chains.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/Analysis/OrderedBasicBlock.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/time.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  ReachingDefinitionsAnalysis
//=============================================================================
//

bool ReachingDefinitionsAnalysis::runOnModule(
		Module& M,
		Config* c,
		bool trackFlagRegs)
{
	_trackFlagRegs = trackFlagRegs;
	_config = c;
	_specialGlobal = AsmInstruction::getLlvmToAsmGlobalVariable(&M);

	clear();
	initializeBasicBlocks(M);
	run();

	_run = true;
	return false;
}

bool ReachingDefinitionsAnalysis::runOnFunction(
		llvm::Function& F,
		Config* c,
		bool trackFlagRegs)
{
	_trackFlagRegs = trackFlagRegs;
	_config = c;
	_specialGlobal = AsmInstruction::getLlvmToAsmGlobalVariable(F.getParent());

	clear();
	initializeBasicBlocks(F);
	run();

	_run = true;
	return false;
}

void ReachingDefinitionsAnalysis::run()
{
	initializeBasicBlocksPrev();
	initializeKillGenSets();
	propagate();
	initializeDefsAndUses();

	LOG << *this << "\n";

	clearInternal();
}

void ReachingDefinitionsAnalysis::initializeBasicBlocks(llvm::Module& M)
{
	for (auto &F : M.getFunctionList())
	{
		initializeBasicBlocks(F);
	}
}

void ReachingDefinitionsAnalysis::initializeBasicBlocks(llvm::Function& F)
{
	for (auto &B : F)
	{
		BasicBlockEntry bbe(&B);

		for (auto &I : B)
		{
			if (auto* l = dyn_cast<LoadInst>(&I))
			{
				if (!isa<GlobalVariable>(l->getPointerOperand())
						&& !isa<AllocaInst>(l->getPointerOperand()))
				{
					continue;
				}
				if (!_trackFlagRegs
						&& _config
						&& _config->isFlagRegister(l->getPointerOperand()))
				{
					continue;
				}

				bbe.uses.push_back(Use(l, l->getPointerOperand()));
			}
			else if (auto* s = dyn_cast<StoreInst>(&I))
			{
				if (!isa<GlobalVariable>(s->getPointerOperand())
						&& !isa<AllocaInst>(s->getPointerOperand()))
				{
					continue;
				}
				if (!_trackFlagRegs
						&& _config
						&& _config->isFlagRegister(s->getPointerOperand()))
				{
					continue;
				}
				if (I.getOperand(1) == _specialGlobal)
				{
					continue;
				}

				bbe.defs.push_back(Definition(s, s->getPointerOperand()));
			}
			else if (auto* a = dyn_cast<AllocaInst>(&I))
			{
				bbe.defs.push_back(Definition(a, a));
			}
			else if (auto* call = dyn_cast<CallInst>(&I))
			{
				unsigned args = call->getNumArgOperands();
				for (unsigned i=0; i<args; ++i)
				{
					Value *a = call->getArgOperand(i);

					if (!_trackFlagRegs
							&& _config
							&& _config->isFlagRegister(a))
					{
						continue;
					}

					if (isa<AllocaInst>(a) || isa<GlobalVariable>(a))
					{
						bbe.uses.push_back( Use(&I, a) );
					}
				}

				// TODO - can allocated object be read in function call?
				// is this ok?
			}
			else
			{
				// Maybe, there are other users or definitions.
			}
		}

		bbMap[&F][&B] = bbe;
	}
}

void ReachingDefinitionsAnalysis::clear()
{
	bbMap.clear();
	_run = false;
}

bool ReachingDefinitionsAnalysis::wasRun() const
{
	return _run;
}

/**
 * Clear internal structures used to compute RDA, but not needed to use it once
 * it is computed.
 */
void ReachingDefinitionsAnalysis::clearInternal()
{
	for (auto& pair1 : bbMap)
	for (auto& pair : pair1.second)
	{
		BasicBlockEntry& bb = pair.second;
		bb.defsOut.clear();
		bb.genDefs.clear();
		bb.killDefs.clear();
	}
}

void ReachingDefinitionsAnalysis::initializeBasicBlocksPrev()
{
	for (auto &pair1 : bbMap)
	for (auto& pair : pair1.second)
	{
		auto B = pair.first;
		auto &entry = pair.second;

		for (auto PI = pred_begin(B), E = pred_end(B); PI != E; ++PI)
		{
			auto* pred = *PI;
			auto p = pair1.second.find(pred);

			assert(p != pair1.second.end() && "we should have all BBs stored in bbMap");

			entry.prevBBs.insert( &p->second );
		}
	}
}

void ReachingDefinitionsAnalysis::initializeKillGenSets()
{
	for (auto &pair1 : bbMap)
	for (auto& pair : pair1.second)
	{
		pair.second.initializeKillDefSets();
	}
}

void ReachingDefinitionsAnalysis::propagate()
{
	for (auto &pair1 : bbMap)
	{
		const Function* fnc = pair1.first;

		std::vector<BasicBlockEntry*> workList;
		workList.reserve(pair1.second.size());
		ReversePostOrderTraversal<const Function*> RPOT(fnc); // Expensive to create
		for (auto I = RPOT.begin(); I != RPOT.end(); ++I)
		{
			const BasicBlock* bb = *I;
			auto fIt = pair1.second.find(bb);
			assert(fIt != pair1.second.end());
			workList.push_back(&(fIt->second));

			fIt->second.changed = true;
		}

		bool changed = true;
		while (changed)
		{
			changed = false;

			for (auto* bbe : workList)
			{
				changed |= bbe->initDefsOut();
			}
		}
	}
}

void ReachingDefinitionsAnalysis::initializeDefsAndUses()
{
	for (auto &pair1 : bbMap)
	for (auto& pair : pair1.second)
	{
		BasicBlockEntry &bb = pair.second;
		OrderedBasicBlock obb(bb.bb);

		for (Use &u : bb.uses)
		{
			for (auto dIt = bb.defs.rbegin(); dIt != bb.defs.rend(); ++dIt)
			{
				Definition &d = *dIt;

				if (d.getSource() != u.src)
				{
					continue;
				}

				if (obb.dominates(d.def, u.use))
				{
					d.uses.insert(&u);
					u.defs.insert(&d);
					break;
				}
			}

			if (u.defs.empty())
			{
				for (auto p : bb.prevBBs)
				for (auto d : p->defsOut)
				{
					if (d->getSource() == u.src)
					{
						d->uses.insert(&u);
						u.defs.insert(d);
					}
				}
			}
		}
	}
}

const BasicBlockEntry& ReachingDefinitionsAnalysis::getBasicBlockEntry(
		const Instruction* I) const
{
	auto* F = I->getFunction();
	auto pair1 = bbMap.find(F);
	assert(pair1 != bbMap.end() && "we do not have this function in bbMap");

	auto* BB = I->getParent();
	auto pair = pair1->second.find(BB);
	assert(pair != pair1->second.end() && "we do not have this basic block in bbMap");

	return pair->second;
}

const DefSet& ReachingDefinitionsAnalysis::defsFromUse(const Instruction* I) const
{
	return getBasicBlockEntry(I).defsFromUse(I);
}

const UseSet& ReachingDefinitionsAnalysis::usesFromDef(const Instruction* I) const
{
	return getBasicBlockEntry(I).usesFromDef(I);
}

const Definition* ReachingDefinitionsAnalysis::getDef(const Instruction* I) const
{
	return getBasicBlockEntry(I).getDef(I);
}

const Use* ReachingDefinitionsAnalysis::getUse(const Instruction* I) const
{
	return getBasicBlockEntry(I).getUse(I);
}

std::ostream& operator<<(std::ostream& out, const ReachingDefinitionsAnalysis& rda)
{
	for (auto &pair1 : rda.bbMap)
	for (auto& pair : pair1.second)
	{
		out << pair.second;
	}
	return out;
}


//
//=============================================================================
//  BasicBlockEntry
//=============================================================================
//

int BasicBlockEntry::newUID = 0;

BasicBlockEntry::BasicBlockEntry(const llvm::BasicBlock* b) :
	bb(b),
	id(newUID++)
{

}

void BasicBlockEntry::initializeKillDefSets()
{
	killDefs.clear();
	genDefs.clear();

	for (auto dIt = defs.rbegin(); dIt != defs.rend(); ++dIt)
	{
		Definition& d = *dIt;

		bool added = (killDefs.insert(d.getSource())).second;
		if (added)
		{
			genDefs.insert(&d);
		}
	}
}

/**
 * REACH_in[B] = Sum (p in pred[B]) (REACH_out[p])
 * REACH_out[B] = GEN[B] + ( REACH_in[B] - KILL[B] )
 */
Changed BasicBlockEntry::initDefsOut()
{
	auto oldSz = defsOut.size();

	if (defsOut.empty() && !genDefs.empty())
	{
		defsOut = std::move(genDefs);
	}

	for (auto* p : prevBBs)
	{
		if (p->changed)
		{
			for (auto* d : p->defsOut)
			{
				if (killDefs.find(d->getSource()) == killDefs.end())
				{
					defsOut.insert(d);
				}
			}
		}
	}

	changed = oldSz != defsOut.size();
	return changed;
}

std::string BasicBlockEntry::getName() const
{
	std::stringstream out;
	std::string name = bb->getName().str();
	if (name.empty())
		out << "bb_" << id;
	else
		out << name;
	return out.str();
}

const DefSet& BasicBlockEntry::defsFromUse(const Instruction* I) const
{
	static DefSet emptyDefSet;
	auto* u = getUse(I);
	return u ? u->defs : emptyDefSet;
}

const UseSet& BasicBlockEntry::usesFromDef(const Instruction* I) const
{
	static UseSet emptyUseSet;
	auto* d = getDef(I);
	return d ? d->uses : emptyUseSet;
}

const Definition* BasicBlockEntry::getDef(const Instruction* I) const
{
	auto dIt = find(defs.begin(), defs.end(), Definition(const_cast<Instruction*>(I), nullptr));
	return dIt != defs.end() ? &(*dIt) : nullptr;
}

const Use* BasicBlockEntry::getUse(const Instruction* I) const
{
	auto uIt = find(uses.begin(), uses.end(), Use(const_cast<Instruction*>(I), nullptr));
	return uIt != uses.end() ? &(*uIt) : nullptr;
}

std::ostream& operator<<(std::ostream& out, const BasicBlockEntry& bbe)
{
	out << "Basic Block = " << bbe.getName() << "\n";

	out << "\n\tPrev:\n";
	for (auto prev : bbe.prevBBs)
	{
		out << "\t\t" << prev->getName() << "\n";
	}

	out << "\n\tDef:\n";
	for (auto d : bbe.defs)
	{
		out << "\t\t" << llvmObjToString(d.def) << "\n";

		for (auto u : d.uses)
			out << "\t\t\t" << llvmObjToString(u->use) << "\n";
	}

	out << "\n\tUses:\n";
	for (auto u : bbe.uses)
	{
		out << "\t\t" << llvmObjToString(u.use) << "\n";

		for (auto d : u.defs)
			out << "\t\t\t" << llvmObjToString(d->def) << "\n";
	}

	out << "\n";
	return out;
}

//
//=============================================================================
//  Definition
//=============================================================================
//

Definition::Definition(llvm::Instruction* d, llvm::Value* s) :
		def(d),
		src(s)
{

}

bool Definition::operator==(const Definition& o) const
{
	return def == o.def;
}

llvm::Value* Definition::getSource()
{
	return src;
}

//
//=============================================================================
//  Use
//=============================================================================
//

Use::Use(llvm::Instruction* u, llvm::Value* s) :
		use(u),
		src(s)
{

}

bool Use::operator==(const Use& o) const
{
	return use == o.use;
}

bool Use::isUndef() const
{
	for (auto* d : defs)
	{
		if (isa<AllocaInst>(d->def) || isa<GlobalVariable>(d->def))
		{
			return true;
		}
	}
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
