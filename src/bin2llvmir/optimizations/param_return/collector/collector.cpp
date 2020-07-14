/**
* @file src/bin2llvmir/optimizations/param_return/collector/collector.cpp
* @brief Collects possible arguments and returns of functions.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <queue>

#include <llvm/IR/CFG.h>
#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/optimizations/param_return/collector/collector.h"
#include "retdec/bin2llvmir/optimizations/param_return/collector/pic32.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

Collector::Collector(
		const Abi* abi,
		Module* m,
		const ReachingDefinitionsAnalysis* rda) :
	_abi(abi),
	_module(m),
	_rda(rda)
{
}

void Collector::collectCallArgs(CallEntry* ce) const
{
	std::vector<llvm::StoreInst*> foundStores;

	collectStoresBeforeInstruction(
		ce->getCallInstruction(),
		foundStores);

	ce->setArgStores(std::move(foundStores));
}

void Collector::collectCallRets(CallEntry* ce) const
{
	std::vector<llvm::LoadInst*> foundLoads;

	collectLoadsAfterInstruction(
		ce->getCallInstruction(),
		foundLoads);

	ce->setRetLoads(std::move(foundLoads));
}

void Collector::collectDefArgs(DataFlowEntry* dataflow) const
{
	if (!dataflow->hasDefinition())
	{
		return;
	}

	auto* f = dataflow->getFunction();

	std::set<Value*> added;
	for (auto it = inst_begin(f), end = inst_end(f); it != end; ++it)
	{
		if (auto* l = dyn_cast<LoadInst>(&*it))
		{
			auto* ptr = l->getPointerOperand();
			if (!_abi->isGeneralPurposeRegister(ptr) && !_abi->isStackVariable(ptr))
			{
				continue;
			}

			auto* use = _rda->getUse(l);
			if (use == nullptr)
			{
				continue;
			}

			if ((use->defs.empty() || use->isUndef())
					&& added.find(ptr) == added.end())
			{
				dataflow->addArg(ptr);
				added.insert(ptr);
			}
		}
	}
}

void Collector::collectDefRets(DataFlowEntry* dataflow) const
{
	if (!dataflow->hasDefinition())
	{
		return;
	}

	auto* f = dataflow->getFunction();

	for (auto it = inst_begin(f), end = inst_end(f); it != end; ++it)
	{
		if (auto* r = dyn_cast<ReturnInst>(&*it))
		{
			ReturnEntry* re = dataflow->createRetEntry(r);
			collectRetStores(re);
		}
	}
}

void Collector::collectRetStores(ReturnEntry* re) const
{
	std::vector<llvm::StoreInst*> foundStores;

// TODO:
// This method should be used only after
// speed comparation of below methods.
//
// In this implementation of parameter
// analysis return type is estimated
// only as last option from colelcted
// values. This iss reason why quicklier
// but not reliable method is used
// instead of more reliable one.
//
//	collectStoresBeforeInstruction(
//		re->getRetInstruction(),
//		foundStores);

	collectStoresInSinglePredecessors(
		re->getRetInstruction(),
		foundStores);

	re->setRetStores(std::move(foundStores));
}

void Collector::collectStoresBeforeInstruction(
		llvm::Instruction* i,
		std::vector<llvm::StoreInst*>& stores) const
{
	if (i == nullptr)
	{
		return;
	}

	std::map<BasicBlock*, std::set<Value*>> seenBlocks;

	auto* block = i->getParent();

	// In case of recursive call of same basic block.
	std::set<Value*> afterValues;
	std::vector<StoreInst*> afterStores;
	collectStoresInInstructionBlock(
			&block->back(),
			afterValues,
			afterStores);

	seenBlocks[block] = std::move(afterValues);

	collectStoresRecursively(i->getPrevNode(), stores, seenBlocks);

	auto& values = seenBlocks[block];

	stores.insert(
		stores.end(),
		afterStores.begin(),
		afterStores.end());

	stores.erase(
		std::remove_if(
			stores.begin(),
			stores.end(),
			[values](StoreInst* s)
			{
				return values.find(
					s->getPointerOperand()) == values.end();
			}),
		stores.end());
}

void Collector::collectStoresInSinglePredecessors(
		llvm::Instruction* i,
		std::vector<llvm::StoreInst*>& stores) const
{
	if (i == nullptr)
	{
		return;
	}

	std::set<BasicBlock*> seenBbs;
	std::set<Value*> disqualifiedValues;

	auto* b = i->getParent();
	seenBbs.insert(b);
	Instruction* prev = i;

	while (true)
	{
		if (prev == &b->front())
		{
			auto* spb = b->getSinglePredecessor();
			if (spb && !spb->empty()
				&& seenBbs.find(spb) == seenBbs.end())
			{
				b = spb;
				prev = &b->back();
				seenBbs.insert(b);
			}
			else
			{
				break;
			}
		}
		else
		{
			prev = prev->getPrevNode();
		}
		if (prev == nullptr)
		{
			break;
		}

		if (isa<CallInst>(prev) || isa<ReturnInst>(prev))
		{
			break;
		}
		else if (auto* store = dyn_cast<StoreInst>(prev))
		{
			auto* ptr = store->getPointerOperand();

			if (disqualifiedValues.find(ptr) == disqualifiedValues.end()
				&& (_abi->isRegister(ptr) || _abi->isStackVariable(ptr)))
			{
				stores.push_back(store);
				disqualifiedValues.insert(ptr);
			}
		}
		else if (auto* load = dyn_cast<LoadInst>(prev))
		{
			auto* ptr = load->getPointerOperand();
			disqualifiedValues.insert(ptr);
		}
	}
}

void Collector::collectStoresRecursively(
			Instruction* i,
			std::vector<StoreInst*>& stores,
			std::map<BasicBlock*, std::set<Value*>>& seen) const
{
	if (i == nullptr)
	{
		return;
	}

	auto* block = i->getParent();

	std::set<Value*> values;
	if (!collectStoresInInstructionBlock(i, values, stores))
	{
		seen[block] = std::move(values);
		return;
	}

	seen.emplace(std::make_pair(block, values));
	std::set<Value*> commonValues;

	for (BasicBlock* pred : predecessors(block))
	{
		if (seen.find(pred) == seen.end())
		{
			collectStoresRecursively(
					&pred->back(),
					stores,
					seen);
		}

		auto& foundValues = seen[pred];
		if (foundValues.empty())
		{
			// Shorcut -> intersection would be empty set.
			commonValues.clear();
			break;
		}

		if (commonValues.empty())
		{
			commonValues = foundValues;
		}
		else
		{
			std::set<Value*> intersection;
			std::set_intersection(
				commonValues.begin(),
				commonValues.end(),
				foundValues.begin(),
				foundValues.end(),
				std::inserter(intersection, intersection.begin()));

			commonValues = std::move(intersection);
		}
	}

	values.insert(commonValues.begin(), commonValues.end());
	seen[block] = values;
}

bool Collector::collectStoresInInstructionBlock(
			Instruction* start,
			std::set<Value*>& values,
			std::vector<StoreInst*>& stores) const
{
	if (start == nullptr)
	{
		return false;
	}

	std::set<llvm::Value*> excluded;

	auto* block = start->getParent();

	for (auto* inst = start; true; inst = inst->getPrevNode())
	{
		if (inst == nullptr)
		{
			return false;
		}
		if (auto* call = dyn_cast<CallInst>(inst))
		{
			auto* calledFnc = call->getCalledFunction();
			if (calledFnc == nullptr || !calledFnc->isIntrinsic())
			{
				return false;
			}
		}
		else if (isa<ReturnInst>(inst))
		{
			return false;
		}
		else if (auto* store = dyn_cast<StoreInst>(inst))
		{
			auto* val = store->getValueOperand();
			auto* ptr = store->getPointerOperand();

			if (!_abi->isRegister(ptr) && !_abi->isStackVariable(ptr))
			{
				excluded.insert(ptr);
			}
			if (auto* l = dyn_cast<LoadInst>(val))
			{
				if (l->getPointerOperand() != store->getPointerOperand())
				{
					excluded.insert(l->getPointerOperand());
				}
			}

			if (excluded.find(ptr) == excluded.end())
			{
				stores.push_back(store);
				values.insert(ptr);
				excluded.insert(ptr);
				excluded.insert(val);
			}
		}
		if (inst == &block->front())
		{
			return true;
		}
	}

	return true;
}

void Collector::collectLoadsAfterInstruction(
		llvm::Instruction* start,
		std::vector<llvm::LoadInst*>& loads) const
{
	if (start == nullptr)
	{
		return;
	}

	std::queue<llvm::Instruction*> next;
	std::set<llvm::Value*> excludedValues;
	std::set<llvm::BasicBlock*> seen;

	BasicBlock* beginBB = start->getParent();
	next.push(start->getNextNode());

	while (!next.empty())
	{
		auto* i = next.front();
		next.pop();

		auto* block = i->getParent();
		seen.insert(block);

		if (collectLoadsAfterInstruction(i, loads, excludedValues))
		{
			for (auto suc : successors(block))
			{
				if (seen.find(suc) == seen.end())
				{
					next.push(&suc->front());
				}
				else if (suc == beginBB)
				{
					next.push(&beginBB->front());
					beginBB = nullptr;
				}
			}
		}
	}
}

bool Collector::collectLoadsAfterInstruction(
		llvm::Instruction* start,
		std::vector<llvm::LoadInst*>& loads,
		std::set<llvm::Value*>& excluded) const
{
	if (start == nullptr)
	{
		return false;
	}

	auto* block = start->getParent();
	for (auto* inst = start; true; inst = inst->getNextNode())
	{
		if (inst == nullptr)
		{
			return false;
		}
		if (auto* call = dyn_cast<CallInst>(inst))
		{
			auto* calledFnc = call->getCalledFunction();
			if (calledFnc == nullptr || !calledFnc->isIntrinsic())
			{
				return false;
			}
		}
		else if (isa<ReturnInst>(inst))
		{
			return false;
		}
		else if (auto* store = dyn_cast<StoreInst>(inst))
		{
			auto* ptr = store->getPointerOperand();
			excluded.insert(ptr);
		}
		else if (auto* load = dyn_cast<LoadInst>(inst))
		{
			auto* ptr = load->getPointerOperand();

			if (excluded.find(ptr) == excluded.end()
				&& ( _abi->isGeneralPurposeRegister(ptr) || _abi->isStackVariable(ptr) ))
			{
				loads.push_back(load);
			}
		}

		if (inst == &block->back())
		{
			return true;
		}
	}

	return true;
}

void Collector::collectCallSpecificTypes(CallEntry* ce) const
{
	if (!ce->getBaseFunction()->isVariadic())
	{
		return;
	}

	if (!extractFormatString(ce))
	{
		return;
	}

	auto wrappedCall = ce->getBaseFunction()->getWrappedCall();

	auto trueCall = wrappedCall ? wrappedCall : ce->getCallInstruction();

	ce->setArgTypes(
		llvm_utils::parseFormatString(
			_module,
			ce->getFormatString(),
			trueCall->getCalledFunction())
	);
}

bool Collector::extractFormatString(CallEntry* ce) const
{
	for (auto& i : ce->args())
	{
		auto inst = std::find_if(
					ce->argStores().begin(),
					ce->argStores().end(),
					[i](StoreInst *st)
					{
						return st->getPointerOperand() == i;
					});

		if (inst != ce->argStores().end())
		{
			std::string str;
			if (storesString(*inst, str))
			{
				ce->setFormatString(str);
				return true;
			}
		}
	}

	return false;
}

bool Collector::storesString(StoreInst* si, std::string& str) const
{
	auto* v = getRoot(si->getValueOperand());
	auto* gv = dyn_cast_or_null<GlobalVariable>(v);

	if (gv == nullptr || !gv->hasInitializer())
	{
		return false;
	}

	auto* init = dyn_cast_or_null<ConstantDataArray>(gv->getInitializer());
	if (init == nullptr)
	{
		if (auto* i = dyn_cast<ConstantExpr>(gv->getInitializer()))
		{
			if (auto* igv = dyn_cast<GlobalVariable>(i->getOperand(0)))
			{
				init = dyn_cast_or_null<ConstantDataArray>(igv->getInitializer());
			}
		}
	}

	if (init == nullptr || !init->isString())
	{
		return false;
	}

	str = init->getAsString();
	return true;
}

llvm::Value* Collector::getRoot(llvm::Value* i) const
{
	std::set<llvm::Value*> seen;
	return _getRoot(i, seen);
}

llvm::Value* Collector::_getRoot(llvm::Value* i, std::set<llvm::Value*>& seen) const
{
	if (seen.count(i))
	{
		return i;
	}
	seen.insert(i);

	i = llvm_utils::skipCasts(i);
	if (auto* ii = dyn_cast<Instruction>(i))
	{
		if (auto* u = _rda->getUse(ii))
		{
			if (u->defs.size() == 1)
			{
				auto* d = (*u->defs.begin())->def;
				if (auto* s = dyn_cast<StoreInst>(d))
				{
					return _getRoot(s->getValueOperand(), seen);
				}
				else
				{
					return d;
				}
			}
			else if (auto* l = dyn_cast<LoadInst>(ii))
			{
				return _getRoot(l->getPointerOperand(), seen);
			}
			else
			{
				return i;
			}
		}
		else if (auto* l = dyn_cast<LoadInst>(ii))
		{
			return _getRoot(l->getPointerOperand(), seen);
		}
		else
		{
			return i;
		}
	}

	return i;
}

//
//=============================================================================
//  CollectorProvider
//=============================================================================
//

Collector::Ptr CollectorProvider::createCollector(
				const Abi* abi,
				Module* m,
				const ReachingDefinitionsAnalysis* rda)
{
	if (abi->isPic32())
	{
		return std::make_unique<CollectorPic32>(abi, m, rda);
	}

	return std::make_unique<Collector>(abi, m, rda);
}

}
}
