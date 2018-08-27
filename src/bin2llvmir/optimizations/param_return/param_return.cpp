/**
* @file src/bin2llvmir/optimizations/param_return/param_return.cpp
* @brief Detect functions' parameters and returns.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* Original implementation:
*   name -- position of format string, position of variadic arg start
*   printf/scanf -- 0, 1
*   __printf_chk -- 1, 2
*   __fprintf_chk -- 2, 3
*   fprintf/fscanf/wsprintfA/wsprintf/sprintf/sscanf -- 1, 2
*   snprintf -- 2, 3
*   __snprintf_chk -- 4, 5
*   ioctl/open/FmtStr -- not handled -- erase arguments
*   wprintf/wscanf -- 0, 1
*   error -- 2, 3
*   error_at_line -- 4, 5
*   other -- not handled -- copy arguments
*/

#include <cassert>
#include <iomanip>
#include <iostream>
#include <limits>

#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/container.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/param_return/param_return.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

llvm::Value* getRoot(ReachingDefinitionsAnalysis& RDA, llvm::Value* i, bool first = true)
{
	static std::set<llvm::Value*> seen;
	if (first)
	{
		seen.clear();
	}
	if (seen.count(i))
	{
		return i;
	}
	seen.insert(i);

	i = llvm_utils::skipCasts(i);
	if (auto* ii = dyn_cast<Instruction>(i))
	{
		if (auto* u = RDA.getUse(ii))
		{
			if (u->defs.size() == 1)
			{
				auto* d = (*u->defs.begin())->def;
				if (auto* s = dyn_cast<StoreInst>(d))
				{
					return getRoot(RDA, s->getValueOperand(), false);
				}
				else
				{
					return d;
				}
			}
			else if (auto* l = dyn_cast<LoadInst>(ii))
			{
				return getRoot(RDA, l->getPointerOperand(), false);
			}
			else
			{
				return i;
			}
		}
		else if (auto* l = dyn_cast<LoadInst>(ii))
		{
			return getRoot(RDA, l->getPointerOperand(), false);
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
//  ParamReturn
//=============================================================================
//

char ParamReturn::ID = 0;

static RegisterPass<ParamReturn> X(
		"param-return",
		"Function parameters and returns optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ParamReturn::ParamReturn() :
		ModulePass(ID)
{

}

bool ParamReturn::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	_image = FileImageProvider::getFileImage(_module);
	_dbgf = DebugFormatProvider::getDebugFormat(_module);
	_lti = LtiProvider::getLti(_module);
	return run();
}

bool ParamReturn::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		Abi* abi,
		FileImage* img,
		DebugFormat* dbgf,
		Lti* lti)
{
	_module = &m;
	_config = c;
	_abi = abi;
	_image = img;
	_dbgf = dbgf;
	_lti = lti;
	return run();
}

bool ParamReturn::run()
{
	if (_config == nullptr)
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	_RDA.runOnModule(*_module, AbiProvider::getAbi(_module));

	collectAllCalls();
	dumpInfo();
	filterCalls();
	dumpInfo();
	applyToIr();

	_RDA.clear();

	return false;
}

/**
 * Collect possible arguments' stores for all calls we want to analyze.
 * At the moment, we analyze only indirect or declared function calls with no
 * arguments inside one basic block.
 */
void ParamReturn::collectAllCalls()
{
	for (auto& f : _module->getFunctionList())
	{
		if (f.isIntrinsic())
		{
			continue;
		}

		_fnc2calls.emplace(
				std::make_pair(
						&f,
						DataFlowEntry(
								_module,
								_RDA,
								_config,
								_abi,
								_image,
								_dbgf,
								_lti,
								&f)));
	}

	for (auto& f : _module->getFunctionList())
	for (auto& b : f)
	for (auto& i : b)
	{
		auto* call = dyn_cast<CallInst>(&i);
		if (call == nullptr || call->getNumArgOperands() != 0)
		{
			continue;
		}

		auto* calledVal = call->getCalledValue();
		auto* calledFnc = call->getCalledFunction();

		if (calledFnc && calledFnc->isIntrinsic())
		{
			continue;
		}

		auto fIt = _fnc2calls.find(calledVal);
		if (fIt == _fnc2calls.end())
		{
			fIt = _fnc2calls.emplace(std::make_pair(
					calledVal,
					DataFlowEntry(
							_module,
							_RDA,
							_config,
							_abi,
							_image,
							_dbgf,
							_lti,
							calledVal))).first;
		}

		fIt->second.addCall(call);
	}
}

void ParamReturn::filterCalls()
{
	for (auto& p : _fnc2calls)
	{
		p.second.filter();
	}
}

void ParamReturn::applyToIr()
{
	for (auto& p : _fnc2calls)
	{
		p.second.applyToIr();
	}

	for (auto& p : _fnc2calls)
	{
		p.second.connectWrappers();
	}
}

/**
 * Dump all the info collected and processed so far.
 */
void ParamReturn::dumpInfo()
{
	LOG << std::endl << "_fnc2calls:" << std::endl;
	for (auto& p : _fnc2calls)
	{
		p.second.dump();
	}
}

//
//=============================================================================
//  CallEntry
//=============================================================================
//

CallEntry::CallEntry(llvm::CallInst* c) :
		call(c)
{

}

void DataFlowEntry::filterNegativeStacks()
{
	args.erase(
		std::remove_if(args.begin(), args.end(),
			[this](const Value* li)
			{
				auto aOff = _config->getStackVariableOffset(li);
				return aOff.isDefined() && aOff < 0;
			}),
		args.end());
}

/**
 * Stack with the lowest (highest negative) offset is the first call argument.
 *
 * Registers are sorted according to position got from abi.
 */
void DataFlowEntry::sortValues(std::vector<Value*> &args) const
{
	auto regs = _abi->parameterRegisters();
	auto fpRegs = _abi->parameterFPRegisters();
	regs.insert(regs.end(), fpRegs.begin(), fpRegs.end());

	std::stable_sort(
			args.begin(),
			args.end(),
			[this, regs, args](Value* a, Value* b) -> bool
	{
		auto aOff = _config->getStackVariableOffset(a);
		auto bOff = _config->getStackVariableOffset(b);

		if (aOff.isUndefined() && bOff.isUndefined())
		{
			auto aId = _abi->getRegisterId(a);
			auto bId = _abi->getRegisterId(b);

			auto it1 = std::find(regs.begin(), regs.end(), aId);
			auto it2 = std::find(regs.begin(), regs.end(), bId);

			return std::distance(it1, it2) > 0;
		}
		else if (aOff.isUndefined() && bOff.isDefined())
		{
			return true;
		}
		else if (aOff.isDefined() && bOff.isUndefined())
		{
			return false;
		}
		else
		{
			return aOff < bOff;
		}
	});
}

void CallEntry::extractFormatString(ReachingDefinitionsAnalysis& _RDA)
{
	for (auto i : possibleArgs)
	{
		auto inst = std::find_if(possibleArgStores.begin(),
					possibleArgStores.end(),
					[i](StoreInst *st)
					{
						return st->getPointerOperand() == i;
					});

		if (inst != possibleArgStores.end())
		{
			std::string str;
			if (instructionStoresString(*inst, str, _RDA))
			{
				formatStr = str;
				return;
			}
		}
	}
}

//
//=============================================================================
//  ReturnEntry
//=============================================================================
//

ReturnEntry::ReturnEntry(llvm::ReturnInst* r) :
		ret(r)
{

}

//
//=============================================================================
//  DataFlowEntry
//=============================================================================
//

DataFlowEntry::DataFlowEntry(
		llvm::Module* m,
		ReachingDefinitionsAnalysis& rda,
		Config* c,
		Abi* abi,
		FileImage* img,
		DebugFormat* dbg,
		Lti* lti,
		llvm::Value* v)
		:
		_module(m),
		_RDA(rda),
		_config(c),
		_abi(abi),
		_image(img),
		_lti(lti),
		called(v)
{
	if (auto* f = getFunction())
	{
		configFnc = c->getConfigFunction(f);
		if (dbg)
		{
			dbgFnc = dbg->getFunction(c->getFunctionAddress(f));
		}

		if (!f->empty())
		{
			addArgLoads();
			addRetStores();
		}
	}

	setTypeFromExtraInfo();
}

bool DataFlowEntry::isFunctionEntry() const
{
	return getFunction() != nullptr;
}

bool DataFlowEntry::isValueEntry() const
{
	return called && !isFunctionEntry();
}

llvm::Value* DataFlowEntry::getValue() const
{
	return called;
}

llvm::Function* DataFlowEntry::getFunction() const
{
	return dyn_cast_or_null<Function>(called);
}

void DataFlowEntry::dump() const
{
	LOG << "\n\t>|" << called->getName().str() << std::endl;
	LOG << "\t>|fnc call : " << isFunctionEntry() << std::endl;
	LOG << "\t>|val call : " << isValueEntry() << std::endl;
	LOG << "\t>|variadic : " << isVarArg << std::endl;
	LOG << "\t>|config f : " << (configFnc != nullptr) << std::endl;
	LOG << "\t>|debug f  : " << (dbgFnc != nullptr) << std::endl;
	LOG << "\t>|wrapp c  : " << llvmObjToString(wrappedCall) << std::endl;
	LOG << "\t>|type set : " << typeSet << std::endl;
	LOG << "\t>|ret type : " << llvmObjToString(retType) << std::endl;
	LOG << "\t>|arg types:" << std::endl;
	for (auto* t : argTypes)
	{
		LOG << "\t\t>|" << llvmObjToString(t) << std::endl;
	}
	LOG << "\t>|arg names:" << std::endl;
	for (auto& n : argNames)
	{
		LOG << "\t\t>|" << n << std::endl;
	}

	LOG << "\t>|calls:" << std::endl;
	for (auto& e : calls)
	{
		LOG << "\t\t>|" << llvmObjToString(e.call) << std::endl;
		LOG << "\t\t\targ stores:" << std::endl;
		for (auto* s : e.possibleArgs)
		{
			LOG << "\t\t\t>|" << llvmObjToString(s) << std::endl;
		}
		LOG << "\t\t\tret loads:" << std::endl;
		for (auto* l : e.possibleRetLoads)
		{
			LOG << "\t\t\t>|" << llvmObjToString(l) << std::endl;
		}
		if (!e.formatStr.empty())
		{
			LOG << "\t\t\t>|format str: " << e.formatStr << std::endl;
		}
	}

	LOG << "\t>|arg loads:" << std::endl;
	for (auto* l : args)
	{
		LOG << "\t\t\t>|" << llvmObjToString(l) << std::endl;
	}

	LOG << "\t>|return stores:" << std::endl;
	for (auto& e : retStores)
	{
		LOG << "\t\t>|" << llvmObjToString(e.ret) << std::endl;
		for (auto* s : e.possibleRetStores)
		{
			LOG << "\t\t\t>|" << llvmObjToString(s) << std::endl;
		}
	}
}

void DataFlowEntry::addArgLoads()
{
	auto* f = getFunction();
	if (f == nullptr)
	{
		return;
	}

	std::set<Value*> added;
	for (auto it = inst_begin(f), end = inst_end(f); it != end; ++it)
	{
		if (auto* l = dyn_cast<LoadInst>(&*it))
		{
			auto* ptr = l->getPointerOperand();
			if (!_abi->valueCanBeParameter(ptr))
			{
				continue;
			}

			auto* use = _RDA.getUse(l);
			if (use == nullptr)
			{
				continue;
			}

			if ((use->defs.empty() || use->isUndef())
					&& added.find(ptr) == added.end())
			{
				args.push_back(ptr);
				added.insert(ptr);
			}
		}
	}
}

void DataFlowEntry::addRetStores()
{
	auto* f = getFunction();
	if (f == nullptr)
	{
		return;
	}

	for (auto it = inst_begin(f), end = inst_end(f); it != end; ++it)
	{
		if (auto* r = dyn_cast<ReturnInst>(&*it))
		{
			ReturnEntry re(r);

			NonIterableSet<BasicBlock*> seenBbs;
			NonIterableSet<Value*> disqualifiedValues;
			auto* b = r->getParent();
			seenBbs.insert(b);
			Instruction* prev = r;
			while (true)
			{
				if (prev == &b->front())
				{
					auto* spb = b->getSinglePredecessor();
					if (spb && !spb->empty() && seenBbs.hasNot(spb))
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

					if (disqualifiedValues.hasNot(ptr)
							&& _abi->canHoldReturnValue(ptr))
					{
						re.possibleRetStores.push_back(store);
						disqualifiedValues.insert(ptr);
					}
				}
				else if (auto* load = dyn_cast<LoadInst>(prev))
				{
					auto* ptr = load->getPointerOperand();
					disqualifiedValues.insert(ptr);
				}
			}

			retStores.push_back(re);
		}
	}
}

void DataFlowEntry::addCall(llvm::CallInst* call)
{
	CallEntry ce(call);

	addCallArgs(call, ce);
	addCallReturns(call, ce);

	calls.push_back(ce);
}

// std::vector?
std::set<Value*> DataFlowEntry::collectArgsFromInstruction(Instruction* startInst, std::map<BasicBlock*, std::set<Value*>> &seenBlocks, std::vector<StoreInst*> *possibleArgStores)
{
	NonIterableSet<Value*> excludedValues;
	auto* block = startInst->getParent();

	std::set<Value*> argStores;

	bool canContinue = true;
	for (auto* inst = startInst; canContinue; inst = inst->getPrevNode())
	{
		if (inst == nullptr)
		{
			return argStores;
		}

		if (auto* call = dyn_cast<CallInst>(inst))
		{
			auto* calledFnc = call->getCalledFunction();
			if (calledFnc == nullptr || !calledFnc->isIntrinsic())
			{
				return argStores;
			}
		}
		else if (auto* store = dyn_cast<StoreInst>(inst))
		{
			auto* val = store->getValueOperand();
			auto* ptr = store->getPointerOperand();

			if (!_abi->valueCanBeParameter(ptr))
			{
				excludedValues.insert(ptr);
			}

			if (auto* l = dyn_cast<LoadInst>(val))
			{
				if (_abi->isX86())
				{
					if (_abi->getRegisterId(l->getPointerOperand()) == X86_REG_EBP
							|| _abi->getRegisterId(l->getPointerOperand()) == X86_REG_RBP)
					{
						excludedValues.insert(ptr);
					}
				}

				if (l->getPointerOperand() != store->getPointerOperand())
				{
					excludedValues.insert(l->getPointerOperand());
				}
			}

			if (excludedValues.hasNot(ptr))
			{
				argStores.insert(ptr);
				excludedValues.insert(ptr);
				excludedValues.insert(val);

				if (possibleArgStores != nullptr)
				{
					possibleArgStores->push_back(store);
				}
			}
		}

		if (inst == &block->front())
		{
			canContinue = false;
		}
	}

	std::set<Value*> commonArgStores;
	// recursive?
	seenBlocks[block] = argStores;

	for (auto pred: predecessors(block))
	{
		std::set<Value*> foundArgs;
		if (seenBlocks.find(pred) == seenBlocks.end())
		{
			foundArgs = collectArgsFromInstruction(&pred->back(), seenBlocks, possibleArgStores);
		}
		else
		{
			foundArgs = seenBlocks[pred];
		}

		if (foundArgs.empty())
		{
			return argStores;
		}

		if (commonArgStores.empty())
		{
			commonArgStores = std::move(foundArgs);
		}
		else
		{
			std::set<Value*> intersection;
			std::set_intersection(
				commonArgStores.begin(),
				commonArgStores.end(),
				foundArgs.begin(),
				foundArgs.end(),
				std::inserter(intersection, intersection.begin()));

			commonArgStores = std::move(intersection);
		}
	}

	argStores.insert(commonArgStores.begin(), commonArgStores.end());

	seenBlocks[block] = argStores;
	return argStores;
}

bool CallEntry::instructionStoresString(
		StoreInst *si,
		std::string& str,
		ReachingDefinitionsAnalysis &_RDA) const
{
	auto* v = getRoot(_RDA, si->getValueOperand());
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

void DataFlowEntry::addCallArgs(llvm::CallInst* call, CallEntry& ce)
{
	std::map<BasicBlock*, std::set<Value*>> seenBlocks;

	auto fromInst = call->getPrevNode();
	if (fromInst == nullptr)
	{
		return;
	}

	auto wantedStores = isVarArg ? &ce.possibleArgStores : nullptr;

	auto possibleArgs = collectArgsFromInstruction(fromInst, seenBlocks, wantedStores);

	ce.possibleArgs.assign(possibleArgs.begin(), possibleArgs.end());
}

void DataFlowEntry::addCallReturns(llvm::CallInst* call, CallEntry& ce)
{
	NonIterableSet<Value*> disqualifiedValues;
	auto* b = call->getParent();
	Instruction* next = call;
	std::set<BasicBlock*> seen;
	seen.insert(b);
	while (true)
	{
		if (next == &b->back())
		{
			auto* ssb = b->getSingleSuccessor();
			if (ssb && !ssb->empty() && ssb != b && seen.count(ssb) == 0)
			{
				b = ssb;
				next = &b->front();
				seen.insert(b);
			}
			else
			{
				break;
			}
		}
		else
		{
			next = next->getNextNode();
		}
		if (next == nullptr)
		{
			break;
		}

		if (auto* call = dyn_cast<CallInst>(next))
		{
			auto* calledFnc = call->getCalledFunction();
			if (calledFnc == nullptr || !calledFnc->isIntrinsic())
			{
				break;
			}
		}
		else if (auto* store = dyn_cast<StoreInst>(next))
		{
			auto* ptr = store->getPointerOperand();
			disqualifiedValues.insert(ptr);
		}
		else if (auto* load = dyn_cast<LoadInst>(next))
		{
			auto* ptr = load->getPointerOperand();

			if (disqualifiedValues.hasNot(ptr)
					&& _abi->canHoldReturnValue(ptr))
			{
				ce.possibleRetLoads.push_back(load);
				disqualifiedValues.insert(ptr);
			}
		}
	}
}

/**
 * TODO: This method just filters register pair of known double type.
 * It should also remove another stack variable and not just for double
 * but every large type -> wordSize * 2
 */
void DataFlowEntry::filterKnownParamPairs()
{
	for (CallEntry& e : calls)
	{
		auto tIt = argTypes.begin();
		auto sIt = e.possibleArgs.begin();

		while (tIt != argTypes.end() && sIt != e.possibleArgs.end())
		{
			Type* t = *tIt;
			auto nextIt = sIt;
			++nextIt;
			if (t->isDoubleTy()
					&& nextIt != e.possibleArgs.end()
					&& _abi->isRegister(*nextIt))
			{
				e.possibleArgs.erase(nextIt);
			}

			++tIt;
			++sIt;
		}
	}
}

void DataFlowEntry::filter()
{
	filterNegativeStacks();
	sortValues(args);

	for (CallEntry& e : calls)
	{
		ParamFilter filter(e.possibleArgs, *_abi, *_config);

		filter.leaveOnlyContinuousStackOffsets();
		filter.leaveOnlyContinuousSequence();

		e.possibleArgs = filter.getParamValues();

		if (isVarArg)
		{
			e.extractFormatString(_RDA);
		}
	}

	if (!isVarArg)
	{
		callsFilterCommonRegisters();
		callsFilterSameNumberOfStacks();
	}

	if (typeSet)
	{
		filterKnownParamPairs();
	}
	else
	{
		setTypeFromUseContext();
	}
}

void DataFlowEntry::callsFilterCommonRegisters()
{
	if (calls.empty())
	{
		return;
	}

	std::set<Value*> commonRegs;

	for (auto& e : calls)
	{
		// TODO: sometimes, we do not find all arg stores.
		// this is a hack, we should manufacture loads even if we do not have
		// stores but know there are some arguments (debug, ...).
		if (e.possibleArgs.empty())
		{
			continue;
		}

		std::set<Value*> regs;
		for (auto r : e.possibleArgs)
		{
			if (_abi->isRegister(r))
			{
				regs.insert(r);
			}
		}

		if (regs.empty())
		{
			commonRegs.erase(commonRegs.begin(), commonRegs.end());
			break;
		}
		else if (commonRegs.empty())
		{
			commonRegs = std::move(regs);
		}
		else
		{
			std::set<Value*> intersect;
			std::set_intersection(
					commonRegs.begin(),
					commonRegs.end(),
					regs.begin(),
					regs.end(),
					std::inserter(intersect, intersect.begin()));

			commonRegs = std::move(intersect);
		}
	}

	for (auto& e : calls)
	{
		e.possibleArgs.erase(
			std::remove_if(
				e.possibleArgs.begin(),
				e.possibleArgs.end(),
				[this, commonRegs](Value* arg)
				{
					return _abi->isRegister(arg)
						&& !commonRegs.count(arg);
				}),
			e.possibleArgs.end());
	}
}

void DataFlowEntry::callsFilterSameNumberOfStacks()
{
	if (calls.empty())
	{
		return;
	}

	std::size_t loads = 0;
	for (auto* l : args)
	{
		if (_config->isStackVariable(l))
		{
			++loads;
		}
	}

	std::size_t stacks = std::numeric_limits<std::size_t>::max();
	for (auto& ce : calls)
	{
		std::size_t ss = 0;
		for (auto* s : ce.possibleArgs)
		{
			if (_config->isStackVariable(s))
			{
				++ss;
			}
		}

		// TODO: all but one have 2 params, receiving have 2 params, one has zero.
		//
		if (ss < stacks && ss != 0 && ss >= loads)
		{
			stacks = ss;
		}
	}
	if (typeSet && stacks < argTypes.size())
	{
		stacks = argTypes.size();
	}

	for (auto& ce : calls)
	{
		std::size_t cntr = 0;
		auto it = ce.possibleArgs.begin();
		while (it != ce.possibleArgs.end())
		{
			auto* s = *it;
			if (!_config->isStackVariable(s))
			{
				++it;
				continue;
			}

			++cntr;
			if (cntr > stacks)
			{
				it = ce.possibleArgs.erase(it);
			}
			else
			{
				++it;
			}
		}
	}
}

void DataFlowEntry::applyToIr()
{
	if (isVarArg)
	{
		applyToIrVariadic();
	}
	else
	{
		applyToIrOrdinary();
	}
}

std::map<CallInst*, std::vector<Value*>> DataFlowEntry::fetchLoadsOfCalls() const
{
	std::map<CallInst*, std::vector<Value*>> loadsOfCalls;

	for (auto& e : calls)
	{
		std::vector<Value*> loads;
		auto* call = e.call;
		for (auto* s : e.possibleArgs)
		{
			auto fIt = specialArgStorage.find(loads.size());
			while (fIt != specialArgStorage.end())
			{
				auto* sl = new LoadInst(fIt->second, "", call);
				loads.push_back(sl);
				fIt = specialArgStorage.find(loads.size());
			}

			auto* l = new LoadInst(s, "", call);
			loads.push_back(l);
		}

		loadsOfCalls[call] = loads;
	}

	return loadsOfCalls;
}

void DataFlowEntry::replaceCalls()
{
	auto loadsOfCalls = fetchLoadsOfCalls();

	for (auto l : loadsOfCalls)
		IrModifier::modifyCallInst(l.first, l.first->getType(), l.second);
}

void DataFlowEntry::applyToIrOrdinary()
{
	Function* analysedFunction = getFunction();

	if (analysedFunction == nullptr)
	{
		replaceCalls();

		return;
	}

	if (analysedFunction->arg_size() > 0)
	{
		return;
	}

	auto loadsOfCalls = fetchLoadsOfCalls();

	llvm::Value* retVal = retType->isFloatingPointTy() ?
		_abi->getFPReturnRegister() : _abi->getReturnRegister();

	std::map<ReturnInst*, Value*> rets2vals;

	if (retVal)
	{
		for (auto& e : retStores)
		{
			auto* l = new LoadInst(retVal, "", e.ret);
			rets2vals[e.ret] = l;
		}
	}

	std::vector<llvm::Value*> argStores;
	for (Value* l : args)
	{
		auto fIt = specialArgStorage.find(argStores.size());
		while (fIt != specialArgStorage.end())
		{
			argStores.push_back(fIt->second);
			fIt = specialArgStorage.find(argStores.size());
		}

		argStores.push_back(l);
	}

	auto paramRegs = _abi->parameterRegisters();

	for (auto& p : loadsOfCalls)
	{
		std::size_t idx = 0;
		for (auto* t : argTypes)
		{
			(void) t;
			if (p.second.size() <= idx)
			{
				if (idx < paramRegs.size())
				{
					auto* r = _abi->getRegister(paramRegs[idx]);
					auto* l = new LoadInst(r, "", p.first);
					p.second.push_back(l);
				}
			}
			++idx;
		}
	}

	auto* oldType = analysedFunction->getType();
	IrModifier irm(_module, _config);
	auto* newFnc = irm.modifyFunction(
			analysedFunction,
			retType,
			argTypes,
			isVarArg,
			rets2vals,
			loadsOfCalls,
			retVal,
			argStores,
			argNames).first;

	LOG << "modify fnc: " << newFnc->getName().str() << " = "
			<< llvmObjToString(oldType) << " -> "
			<< llvmObjToString(newFnc->getType()) << std::endl;

	called = newFnc;
}

void DataFlowEntry::applyToIrVariadic()
{
	auto paramRegs = _abi->parameterRegisters();
	auto paramFPRegs = _abi->parameterFPRegisters();
	auto doubleParamRegs = _abi->doubleParameterRegisters();

	llvm::Value* retVal = nullptr;
	std::map<ReturnInst*, Value*> rets2vals;
	std::vector<llvm::Value*> argStores;
	std::map<llvm::CallInst*, std::vector<llvm::Value*>> loadsOfCalls;

	for (CallEntry& ce : calls)
	{
		auto* fnc = ce.call->getFunction();
		auto* calledFnc = ce.call->getCalledFunction();

		LOG << llvmObjToString(ce.call) << std::endl;
		LOG << "\tformat : " << ce.formatStr << std::endl;

		// get lowest stack offset
		//
		int stackOff = std::numeric_limits<int>::max();
		for (Value* s : ce.possibleArgs)
		{
			if (_config->isStackVariable(s))
			{
				auto so = _config->getStackVariableOffset(s);
				if (so < stackOff)
				{
					stackOff = so;
				}
			}
		}
		LOG << "\tlowest : " << std::dec << stackOff << std::endl;

		//
		//
		auto* wrapCall = isSimpleWrapper(calledFnc);
		auto* wrapFnc = wrapCall ? wrapCall->getCalledFunction() : calledFnc;
		std::vector<llvm::Type*> ttypes = llvm_utils::parseFormatString(
				_module,
				ce.formatStr,
				wrapFnc);

		if (_config->getConfig().architecture.isPic32())
		{
			for (size_t i = 0; i < ttypes.size(); ++i)
			{
				if (ttypes[i]->isDoubleTy())
				{
					ttypes[i] = Type::getFloatTy(_module->getContext());
				}
			}
		}

		//
		//
		int off = stackOff;
		std::vector<Value*> args;

		size_t faIdx = 0;
		size_t aIdx = 0;

		std::vector<llvm::Type*> types = argTypes;
		types.insert(types.end(), ttypes.begin(), ttypes.end());

		for (Type* t : types)
		{
			LOG << "\ttype : " << llvmObjToString(t) << std::endl;
			int sz = static_cast<int>(_abi->getTypeByteSize(t));
			sz = sz > 4 ? 8 : 4;

			if (t->isFloatTy() && _abi->usesFPRegistersForParameters() && faIdx < paramFPRegs.size())
			{

				auto* r = _abi->getRegister(paramFPRegs[faIdx]);
				if (r)
				{
					args.push_back(r);
				}
				++faIdx;
			}
			else if (t->isDoubleTy() && _abi->usesFPRegistersForParameters() && faIdx < doubleParamRegs.size())
			{
				auto* r = _abi->getRegister(doubleParamRegs[faIdx]);
				if (r)
				{
					args.push_back(r);
				}
				++faIdx;
				++faIdx;
			}
			else if (aIdx < paramRegs.size())
			{
				auto* r = _abi->getRegister(paramRegs[aIdx]);
				if (r)
				{
					args.push_back(r);
				}

				// TODO: register pairs -> if size is more than arch size
				if (sz > ws)
				{
					++aIdx;
				}

				++aIdx;
			}
			else
			{
				auto* st = _config->getLlvmStackVariable(fnc, off);
				if (st)
				{
					args.push_back(st);
				}

				off += sz;
			}
		}

		//
		//
		unsigned idx = 0;
		std::vector<Value*> loads;
		for (auto* a : args)
		{
			Value* l = new LoadInst(a, "", ce.call);
			LOG << "\t\t" << llvmObjToString(l) << std::endl;

			if (types.size() > idx)
			{
				l = IrModifier::convertValueToType(l, types[idx], ce.call);
			}

			loads.push_back(l);
			++idx;
		}

		if (!loads.empty())
		{
			loadsOfCalls[ce.call] = loads;
		}
	}

	retVal = retType->isFloatingPointTy() ?
		_abi->getFPReturnRegister() : _abi->getReturnRegister();

	if (retVal)
	{
		for (auto& e : retStores)
		{
			auto* l = new LoadInst(retVal, "", e.ret);
			rets2vals[e.ret] = l;
		}
	}

	auto* fnc = getFunction();
	auto* oldType = fnc->getType();

	IrModifier irm(_module, _config);
	auto* newFnc = irm.modifyFunction(
			fnc,
			retType,
			argTypes,
			isVarArg,
			rets2vals,
			loadsOfCalls,
			retVal,
			argStores,
			argNames).first;

	LOG << "modify fnc: " << newFnc->getName().str() << " = "
			<< llvmObjToString(oldType) << " -> "
			<< llvmObjToString(newFnc->getType()) << std::endl;

	called = newFnc;
}

void DataFlowEntry::connectWrappers()
{
	auto* fnc = getFunction();
	if (fnc == nullptr || wrappedCall == nullptr)
	{
		return;
	}

	wrappedCall = nullptr;
	for (inst_iterator I = inst_begin(fnc), E = inst_end(fnc); I != E; ++I)
	{
		if (auto* c = dyn_cast<CallInst>(&*I))
		{
			auto* cf = c->getCalledFunction();
			if (cf && !cf->isIntrinsic()) // && cf->isDeclaration())
			{
				wrappedCall = c;
				break;
			}
		}
	}

	if (wrappedCall == nullptr)
	{
		return;
	}

	if (wrappedCall->getNumArgOperands() != fnc->getArgumentList().size())
	{
		// TODO: enable assert and inspect these cases.
		return;
	}
	assert(wrappedCall->getNumArgOperands() == fnc->getArgumentList().size());

	unsigned i = 0;
	for (auto& a : fnc->getArgumentList())
	{
		auto* conv = IrModifier::convertValueToType(&a, wrappedCall->getArgOperand(i)->getType(), wrappedCall);
		wrappedCall->setArgOperand(i++, conv);
	}

	//
	//
	std::set<CallInst*> calls;
	for (auto* u : fnc->users())
	{
		if (auto* c = dyn_cast<CallInst>(u))
		{
			// inline all wrapped functions
			// TODO: only really simple fncs, or from .plt, etc.?
//			if (fnc->isVarArg())
			{
				calls.insert(c);
			}
		}
	}

	auto* wrappedFnc = wrappedCall->getCalledFunction();
	assert(wrappedFnc);
	for (auto* c : calls)
	{
		// todo: should not happen?
		if (c->getType()->isVoidTy() && !wrappedFnc->getReturnType()->isVoidTy())
		{
			continue;
		}

		std::vector<Value*> args;
		unsigned numParams = wrappedFnc->getFunctionType()->getNumParams();
		unsigned i = 0;
		for (auto& a : c->arg_operands())
		{
			if (i >= numParams) // var args fncs
			{
				assert(wrappedFnc->isVarArg());
				args.push_back(a);
			}
			else
			{
				auto* conv = IrModifier::convertValueToType(a, wrappedFnc->getFunctionType()->getParamType(i++), c);
				args.push_back(conv);
			}
		}
		auto* nc = CallInst::Create(wrappedFnc, args, "", c);
		auto* resConv = IrModifier::convertValueToTypeAfter(nc, c->getType(), nc);
		c->replaceAllUsesWith(resConv);
		c->eraseFromParent();
	}
}

llvm::CallInst* DataFlowEntry::isSimpleWrapper(llvm::Function* fnc)
{
	auto ai = AsmInstruction(fnc);
	if (ai.isInvalid())
	{
		return nullptr;
	}

	bool single = true;
	auto next = ai.getNext();
	while (next.isValid())
	{
		if (!next.empty() && !isa<TerminatorInst>(next.front()))
		{
			single = false;
			break;
		}
		next = next.getNext();
	}

	// Pattern
	// .text:00008A38                 LDR     R0, =aCCc       ; "C::cc()"
	// .text:00008A3C                 B       puts
	// .text:00008A40 off_8A40        DCD aCCc
	// TODO: make better wrapper detection. In wrapper, wrapped function params
	// should not be set like in this example.
	//
	if (ai && next)
	{
		if (_image->getConstantDefault(next.getEndAddress()))
		{
			auto* l = ai.getInstructionFirst<LoadInst>();
			auto* s = ai.getInstructionFirst<StoreInst>();
			auto* c = next.getInstructionFirst<CallInst>();
			if (l && s && c && isa<GlobalVariable>(l->getPointerOperand())
					&& s->getPointerOperand()->getName() == "r0")
			{
				auto gvA = _config->getGlobalAddress(cast<GlobalVariable>(l->getPointerOperand()));
				if (gvA == next.getEndAddress())
				{
					return nullptr;
				}
			}
		}
	}

	if (single)
	{
		for (auto& i : ai)
		{
			if (auto* c = dyn_cast<CallInst>(&i))
			{
				auto* cf = c->getCalledFunction();
				if (cf && !cf->isIntrinsic()) // && cf->isDeclaration())
				{
					return c;
				}
			}
		}
	}

	unsigned aiNum = 0;
	bool isSmall = true;
	next = ai;
	while (next.isValid())
	{
		++aiNum;
		next = next.getNext();
		if (aiNum > 4)
		{
			isSmall = false;
			break;
		}
	}
	auto* s = _image->getImage()->getSegmentFromAddress(ai.getAddress());
	if ((s && s->getName() == ".plt") || isSmall)
	{
		for (inst_iterator it = inst_begin(fnc), rIt = inst_end(fnc);
				it != rIt; ++it)
		{
			if (auto* l = dyn_cast<LoadInst>(&*it))
			{
				std::string n = l->getPointerOperand()->getName();
				if (n == "lr" || n == "sp")
				{
					return nullptr;
				}
			}
			else if (auto* s = dyn_cast<StoreInst>(&*it))
			{
				std::string n = s->getPointerOperand()->getName();
				if (n == "lr" || n == "sp")
				{
					return nullptr;
				}
			}
			else if (auto* c = dyn_cast<CallInst>(&*it))
			{
				auto* cf = c->getCalledFunction();
				if (cf && !cf->isIntrinsic() && cf->isDeclaration())
				{
					return c;
				}
			}
		}
	}

	return nullptr;
}

void DataFlowEntry::setTypeFromExtraInfo()
{
	auto* fnc = getFunction();
	if (fnc == nullptr)
	{
		return;
	}

	// Main
	//
	if (fnc->getName() == "main")
	{
		argTypes.push_back(Type::getInt32Ty(_module->getContext()));
		argTypes.push_back(PointerType::get(
				PointerType::get(
						Type::getInt8Ty(_module->getContext()),
						0),
				0));
		argNames.push_back("argc");
		argNames.push_back("argv");
		retType = Type::getInt32Ty(_module->getContext());
		typeSet = true;
		return;
	}

	// LTI info.
	//
	auto* cf = _config->getConfigFunction(fnc);
	if (cf && (cf->isDynamicallyLinked() || cf->isStaticallyLinked()))
	{
		auto fp = _lti->getPairFunctionFree(cf->getName());
		if (fp.first)
		{
			for (auto& a : fp.first->args())
			{
				argTypes.push_back(a.getType());
				argNames.push_back(a.getName());
			}
			if (fp.first->isVarArg())
			{
				isVarArg = true;
			}
			retType = fp.first->getReturnType();
			typeSet = true;

			std::string declr = fp.second->getDeclaration();
			if (!declr.empty())
			{
				cf->setDeclarationString(declr);
			}

			// TODO: we could rename function if LTI name differs.
			// e.g. scanf vs _scanf.
			//
//			if (fp.first->getName() != fnc->getName())
//			{
//				IrModifier irmodif(_module, _config);
//				irmodif.renameFunction(fnc, fp.first->getName());
//			}

			return;
		}
	}

	// Debug info.
	//
	if (dbgFnc)
	{
		for (auto& a : dbgFnc->parameters)
		{
			auto* t = llvm_utils::stringToLlvmTypeDefault(_module, a.type.getLlvmIr());
			argTypes.push_back(t);
			argNames.push_back(a.getName());
		}
		if (dbgFnc->isVariadic())
		{
			isVarArg = true;
		}
		retType = llvm_utils::stringToLlvmTypeDefault(
				_module,
				dbgFnc->returnType.getLlvmIr());
		typeSet = true;
		return;
	}

	if (_config->getConfig().isIda() && configFnc)
	{
		for (auto& a : configFnc->parameters)
		{
			auto* t = llvm_utils::stringToLlvmTypeDefault(_module, a.type.getLlvmIr());
			argTypes.push_back(t);
			argNames.push_back(a.getName());

			if (_config->getConfig().architecture.isX86())
			{
				std::string regName;
				if (a.getStorage().isRegister(regName))
				{
					if (auto* reg = _config->getLlvmRegister(regName))
					{
						specialArgStorage[argTypes.size()-1] = reg;
					}
				}
			}
		}
		if (configFnc->isVariadic())
		{
			isVarArg = true;
		}
		retType = llvm_utils::stringToLlvmTypeDefault(
				_module,
				configFnc->returnType.getLlvmIr());
		if (!argTypes.empty())
		{
			typeSet = true;
		}
		return;
	}

	// Wrappers.
	//
	if ((wrappedCall = isSimpleWrapper(fnc)))
	{
		auto* wf = wrappedCall->getCalledFunction();
		auto* ltiFnc = _lti->getLlvmFunctionFree(wf->getName());
		if (ltiFnc)
		{
			for (auto& a : ltiFnc->args())
			{
				argTypes.push_back(a.getType());
				argNames.push_back(a.getName());
			}
			if (ltiFnc->isVarArg())
			{
				isVarArg = true;
			}
			retType = ltiFnc->getReturnType();
			typeSet = true;
			return;
		}
		else
		{
			wrappedCall = nullptr;
		}
	}
}

void DataFlowEntry::setTypeFromUseContext()
{
	setReturnType();
	setArgumentTypes();
	typeSet = true;
}

void DataFlowEntry::setReturnType()
{
	llvm::Value* retVal = _abi->getReturnRegister();

	retType = retVal ?
			retVal->getType()->getPointerElementType() :
			Type::getVoidTy(_module->getContext());
}

void DataFlowEntry::setArgumentTypes()
{
	if (calls.empty())
	{
		argTypes.insert(
				argTypes.end(),
				args.size(),
				Abi::getDefaultType(_module));
	}
	else
	{
		CallEntry* ce = &calls.front();
		for (auto& c : calls)
		{
			if (!c.possibleArgs.empty())
			{
				ce = &c;
				break;
			}
		}

		for (auto st: ce->possibleArgs)
		{
			auto op = st;

			if (_abi->isRegister(op) && !_abi->isGeneralPurposeRegister(op))
			{
				argTypes.push_back(Abi::getDefaultFPType(_module));
			}
			else
			{
				argTypes.push_back(Abi::getDefaultType(_module));
			}
		}
	}
}

//
//=============================================================================
//  ParamFilter
//=============================================================================
//

ParamFilter::ParamFilter(
		const std::vector<Value*>& paramValues,
		const Abi& abi,
		Config& config)
		:
		_abi(abi),
		_config(config)
{
	separateParamValues(paramValues);

	orderRegistersBy(_fpRegValues, _abi.parameterFPRegisters());
	orderRegistersBy(_regValues, _abi.parameterRegisters());
	orderStacks(_stackValues);
}

void ParamFilter::separateParamValues(const std::vector<Value*>& paramValues)
{
	auto regs = _abi.parameterRegisters();

	for (auto pv: paramValues)
	{
		if (_config.isStackVariable(pv))
		{
			_stackValues.push_back(pv);
		}
		else if (std::find(regs.begin(), regs.end(),
				_abi.getRegisterId(pv)) != regs.end())
		{
			_regValues.push_back(_abi.getRegisterId(pv));
		}
		else
		{
			_fpRegValues.push_back(_abi.getRegisterId(pv));
		}
	}
}

void ParamFilter::orderStacks(std::vector<Value*>& stacks, bool asc) const
{
	std::stable_sort(
			stacks.begin(),
			stacks.end(),
			[this, asc](Value* a, Value* b) -> bool
	{
		auto aOff = _config.getStackVariableOffset(a);
		auto bOff = _config.getStackVariableOffset(b);

		bool ascOrd = aOff < bOff;

		return asc ? ascOrd : !ascOrd;
	});
}

void ParamFilter::orderRegistersBy(
				std::vector<uint32_t>& regs,
				const std::vector<uint32_t>& orderedVector) const
{
	std::stable_sort(
			regs.begin(),
			regs.end(),
			[this, orderedVector](uint32_t a, uint32_t b) -> bool
	{
		auto it1 = std::find(orderedVector.begin(), orderedVector.end(), a);
		auto it2 = std::find(orderedVector.begin(), orderedVector.end(), b);

		return std::distance(it1, it2) > 0;
	});
}

void ParamFilter::leaveOnlyContinuousStackOffsets()
{
	retdec::utils::Maybe<int> prevOff;
	int gap = _abi.wordSize()*2/8;

	auto it = _stackValues.begin();
	while (it != _stackValues.end())
	{
		auto off = _config.getStackVariableOffset(*it);

		if (prevOff.isUndefined())
		{
			prevOff = off;
		}
		else if (std::abs(prevOff - off) > gap)
		{
			it = _stackValues.erase(it);
			continue;
		}
		else
		{
			prevOff = off;
		}

		++it;
	}
}

void ParamFilter::leaveOnlyContinuousSequence()
{
	if (_abi.parameterRegistersOverlay())
	{
		applyAlternatingRegistersFilter();
	}
	else
	{
		applySequentialRegistersFilter();
	}
}

void ParamFilter::applyAlternatingRegistersFilter()
{
	auto templRegs = _abi.parameterRegisters();
	auto fpTemplRegs = _abi.parameterFPRegisters();

	size_t idx = 0;
	auto it = _regValues.begin();
	auto fIt = _fpRegValues.begin();

	while (idx < fpTemplRegs.size() && idx < templRegs.size())
	{
		if (it == _regValues.end() && fIt == _fpRegValues.end())
		{
			_stackValues.clear();
			return;
		}

		if (it != _regValues.end() && *it == templRegs[idx])
		{
			it++;
		}
		else if (fIt != _fpRegValues.end() && *fIt == fpTemplRegs[idx])
		{
			fIt++;
		}
		else
		{
			_regValues.erase(it, _regValues.end());
			_fpRegValues.erase(fIt, _fpRegValues.end());
			_stackValues.clear();

			return;
		}

		idx++;
	}
}

void ParamFilter::applySequentialRegistersFilter()
{
	auto it = _regValues.begin();
	for (auto regId : _abi.parameterRegisters())
	{
		if (it == _regValues.end())
		{
			_stackValues.clear();
			break;
		}

		if (regId != *it)
		{
			_regValues.erase(it, _regValues.end());
			_stackValues.clear();
			break;
		}

		it++;
	}

	auto fIt = _fpRegValues.begin();
	for (auto regId : _abi.parameterFPRegisters())
	{
		if (fIt == _fpRegValues.end())
		{
			break;
		}

		if (regId != *fIt)
		{
			_fpRegValues.erase(fIt, _fpRegValues.end());
			break;
		}

		fIt++;
	}
}

std::vector<Value*> ParamFilter::getParamValues() const
{
	std::vector<Value*> paramValues;

	for (auto i : _regValues)
	{
		paramValues.push_back(_abi.getRegister(i));
	}

	for (auto i : _fpRegValues)
	{
		paramValues.push_back(_abi.getRegister(i));
	}

	paramValues.insert(paramValues.end(), _stackValues.begin(), _stackValues.end());

	return paramValues;
}

} // namespace bin2llvmir
} // namespace retdec
