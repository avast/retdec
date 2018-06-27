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

//dumpModuleToFile(_module);

	collectAllCalls();
	dumpInfo();
	filterCalls();
	dumpInfo();
	applyToIr();

	_RDA.clear();

//dumpModuleToFile(_module);
//exit(1);

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

bool registerCanBeParameterAccordingToAbi(Config* _config, llvm::Value* val)
{
	if (!_config->isRegister(val))
	{
		return true;
	}

	if (_config->getConfig().architecture.isX86())
	{
		return false;
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		static std::set<std::string> names = {"r3", "r4", "r5", "r6", "r7", "r8", "r9"};
		if (names.find(val->getName()) == names.end())
		{
			return false;
		}
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		static std::set<std::string> names = {"r0", "r1", "r2", "r3"};
		if (names.find(val->getName()) == names.end())
		{
			return false;
		}
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		static std::set<std::string> names = {"a0", "a1", "a2", "a3"};
		if (names.find(val->getName()) == names.end())
		{
			return false;
		}
	}

	return true;
}

/**
 * Remove all registers that are not used to pass argument according to ABI.
 */
void CallEntry::filterRegisters(Config* _config)
{
	auto it = possibleArgStores.begin();
	while (it != possibleArgStores.end())
	{
		auto* op = (*it)->getPointerOperand();
		if (!registerCanBeParameterAccordingToAbi(_config, op))
		{
			it = possibleArgStores.erase(it);
		}
		else
		{
			++it;
		}
	}
}

void DataFlowEntry::filterRegistersArgLoads()
{
	auto it = argLoads.begin();
	while (it != argLoads.end())
	{
		auto* op = (*it)->getPointerOperand();
		if (!registerCanBeParameterAccordingToAbi(_config, op))
		{
			it = argLoads.erase(it);
		}
		else
		{
			auto aOff = _config->getStackVariableOffset(op);
			if (aOff.isDefined() && aOff < 0)
			{
				it = argLoads.erase(it);
			}
			else
			{
				++it;
			}
		}
	}
}

/**
 * Stack with the lowest (highest negative) offset is the first call argument.
 */
void CallEntry::filterSort(Config* _config)
{
	auto& stores = possibleArgStores;

	std::stable_sort(
			stores.begin(),
			stores.end(),
			[_config](StoreInst* a, StoreInst* b) -> bool
	{
		auto aOff = _config->getStackVariableOffset(a->getPointerOperand());
		auto bOff = _config->getStackVariableOffset(b->getPointerOperand());

		if (aOff.isUndefined() && bOff.isUndefined())
		{
			return _config->getConfigRegisterNumber(a->getPointerOperand()) <
					_config->getConfigRegisterNumber(b->getPointerOperand());
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

void DataFlowEntry::filterSortArgLoads()
{
	std::stable_sort(
			argLoads.begin(),
			argLoads.end(),
			[this](LoadInst* a, LoadInst* b) -> bool
	{
		auto aOff = _config->getStackVariableOffset(a->getPointerOperand());
		auto bOff = _config->getStackVariableOffset(b->getPointerOperand());

		if (aOff.isUndefined() && bOff.isUndefined())
		{
			return _config->getConfigRegisterNumber(a->getPointerOperand()) <
					_config->getConfigRegisterNumber(b->getPointerOperand());
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

/**
 * Arguments are stored into stack variables which go one after another,
 * there can be no big stack offset gaps.
 */
void CallEntry::filterLeaveOnlyContinuousStackOffsets(Config* _config)
{
	retdec::utils::Maybe<int> prevOff;
	auto it = possibleArgStores.begin();
	while (it != possibleArgStores.end())
	{
		auto* s = *it;
		auto off = _config->getStackVariableOffset(s->getPointerOperand());
		auto* val = llvm_utils::skipCasts(s->getValueOperand());

		int gap = 8;
//		int gap = 4;
		if (val->getType()->isFloatingPointTy())
		{
			gap = 8;
		}

		if (off.isUndefined())
		{
			++it;
			continue;
		}
		if (prevOff.isUndefined())
		{
			prevOff = off;
		}
		else if (std::abs(prevOff - off) > gap)
		{
			it = possibleArgStores.erase(it);
			continue;
		}
		else
		{
			prevOff = off;
		}

		++it;
	}
}

void CallEntry::filterLeaveOnlyNeededStackOffsets(Config* _config)
{
	int regNum = 0;
	auto it = possibleArgStores.begin();
	while (it != possibleArgStores.end())
	{
		auto* s = *it;
		auto* op = s->getPointerOperand();
		auto off = _config->getStackVariableOffset(op);

		if (_config->isRegister(op))
		{
			++regNum;
			++it;
			continue;
		}
		else if (off.isDefined())
		{
			if (_config->getConfig().architecture.isX86())
			{
				// nothing
			}
			else if (_config->getConfig().architecture.isPpc())
			{
				if (regNum == 7)
				{
					// nothing
				}
				else
				{
					it = possibleArgStores.erase(it);
					continue;
				}
			}
			else if (_config->getConfig().architecture.isArmOrThumb()
					|| _config->getConfig().architecture.isMipsOrPic32())
			{
				if (regNum == 4)
				{
					// nothing
				}
				else
				{
					it = possibleArgStores.erase(it);
					continue;
				}
			}
			else
			{
				// nothing
			}
		}

		++it;
	}
}

void CallEntry::extractFormatString(ReachingDefinitionsAnalysis& _RDA)
{
	for (auto* s : possibleArgStores)
	{
		auto* v = getRoot(_RDA, s->getValueOperand());
		auto* gv = dyn_cast_or_null<GlobalVariable>(v);

		if (gv == nullptr || !gv->hasInitializer())
		{
			continue;
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
			continue;
		}

		formatStr = init->getAsString();
		break;
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
		for (auto* s : e.possibleArgStores)
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
	for (auto* l : argLoads)
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
			if (!_config->isStackVariable(ptr) && !_config->isRegister(ptr))
			{
				continue;
			}
			if (_config->isFlagRegister(ptr))
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
				argLoads.push_back(l);
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
							&& !_config->isFlagRegister(ptr)
							&& (_config->isStackVariable(ptr) || _config->isRegister(ptr)))
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
	// Pattern:
	// bc pc   // call prantf()
	// align 4
	// prantf():
	// ...
	// Call has no args because it is stub, if we let it, it will destroy
	// all arg from all other calls.
	//
	// TODO:
	// => ignore - this is an ugly hack, solve somehow better.
	//
	if (_config->getConfig().architecture.isArmOrThumb())
	{
		if (auto ai = AsmInstruction(call))
		{
			auto* cs = ai.getCapstoneInsn();
			if ((cs->id == ARM_INS_B || cs->id == ARM_INS_BX)
					&& cs->detail->arm.op_count == 1
					&& cs->detail->arm.operands[0].type == ARM_OP_REG
					&& cs->detail->arm.operands[0].reg == ARM_REG_PC)
			{
				return;
			}
		}
	}

	CallEntry ce(call);

	addCallArgs(call, ce);
	addCallReturns(call, ce);

	calls.push_back(ce);
}

void DataFlowEntry::addCallArgs(llvm::CallInst* call, CallEntry& ce)
{
	NonIterableSet<Value*> disqualifiedValues;
	unsigned maxUsedRegNum = 0;
	auto* b = call->getParent();
	Instruction* prev = call;
	std::set<BasicBlock*> seen;
	seen.insert(b);
	while (true)
	{
		if (prev == &b->front())
		{
			auto* spb = b->getSinglePredecessor();
			if (spb && !spb->empty() && spb != b && seen.count(spb) == 0)
			{
				b = spb;
				prev = &b->back();
				seen.insert(b);
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

		if (auto* call = dyn_cast<CallInst>(prev))
		{
			auto* calledFnc = call->getCalledFunction();
			if (calledFnc == nullptr || !calledFnc->isIntrinsic())
			{
				break;
			}
		}
		else if (auto* store = dyn_cast<StoreInst>(prev))
		{
			auto* val = store->getValueOperand();
			auto* ptr = store->getPointerOperand();

			if (!_config->isStackVariable(ptr) && !_config->isRegister(ptr))
			{
				disqualifiedValues.insert(ptr);
			}

			if (auto* l = dyn_cast<LoadInst>(val))
			{
				if (l->getPointerOperand()->getName() == "ebp"
						|| l->getPointerOperand()->getName() == "rbp")
				{
					disqualifiedValues.insert(ptr);
				}
				if (_config->isRegister(ptr)
						&& _config->isRegister(l->getPointerOperand())
						&& ptr != l->getPointerOperand())
				{
					disqualifiedValues.insert(l->getPointerOperand());
				}
			}

			if (disqualifiedValues.hasNot(ptr)
					&& !_config->isFlagRegister(ptr)
					&& (isa<AllocaInst>(ptr) || _config->isRegister(ptr)))
			{
				ce.possibleArgStores.push_back(store);
				disqualifiedValues.insert(ptr);
				disqualifiedValues.insert(store);

				if (_config->isGeneralPurposeRegister(ptr)
						|| _config->isFloatingPointRegister(ptr))
				{
					auto rn = _config->getConfigRegisterNumber(ptr);
					if (rn.isDefined() && rn > maxUsedRegNum)
					{
						maxUsedRegNum = rn;
					}
				}
			}
		}
	}
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
					&& !_config->isFlagRegister(ptr)
					&& (_config->isStackVariable(ptr) || _config->isRegister(ptr)))
			{
				ce.possibleRetLoads.push_back(load);
				disqualifiedValues.insert(ptr);
			}
		}
	}
}

void DataFlowEntry::filter()
{
	if (!isVarArg)
	{
		callsFilterCommonRegisters();
	}

	filterRegistersArgLoads();
	filterSortArgLoads();

	for (CallEntry& e : calls)
	{
		e.filterRegisters(_config);
		e.filterSort(_config);
		e.filterLeaveOnlyContinuousStackOffsets(_config);
		e.filterLeaveOnlyNeededStackOffsets(_config);

		if (isVarArg)
		{
			e.extractFormatString(_RDA);
		}
	}

	if (!isVarArg)
	{
		callsFilterSameNumberOfStacks();
	}

	if (typeSet)
	{
		for (CallEntry& e : calls)
		{
			auto tIt = argTypes.begin();
			auto sIt = e.possibleArgStores.begin();

			while (tIt != argTypes.end() && sIt != e.possibleArgStores.end())
			{
				Type* t = *tIt;
				auto nextIt = sIt;
				++nextIt;
				if (t->isDoubleTy()
						&& nextIt != e.possibleArgStores.end()
						&& _config->isRegister((*nextIt)->getPointerOperand()))
				{
					e.possibleArgStores.erase(nextIt);
				}

				++tIt;
				++sIt;
			}
		}
	}
	else
	{
		if (_config->getConfig().architecture.isArmOrThumb())
		{
			static std::vector<std::string> armNames =
					{"r0", "r1", "r2", "r3"};

			for (CallEntry& e : calls)
			{
				std::size_t idx = 0;
				auto sIt = e.possibleArgStores.begin();
				while (sIt != e.possibleArgStores.end() && idx < armNames.size())
				{
					StoreInst* s = *sIt;
					if (s->getPointerOperand()->getName() != armNames[idx])
					{
						e.possibleArgStores.erase(sIt, e.possibleArgStores.end());
						break;
					}

					++sIt;
					++idx;
				}
			}
		}
	}

	setTypeFromUseContext();
}

void DataFlowEntry::callsFilterCommonRegisters()
{
	if (calls.empty())
	{
		return;
	}

	std::set<Value*> commonRegs;

	for (auto* s : calls.front().possibleArgStores)
	{
		Value* r = s->getPointerOperand();
		if (_config->isRegister(r))
		{
			commonRegs.insert(r);
		}
	}

	for (auto& e : calls)
	{
		// TODO: sometimes, we do not find all arg stores.
		// this is a hack, we should manufacture loads even if we do not have
		// stores but know there are some arguments (debug, ...).
		if (e.possibleArgStores.empty())
		{
			continue;
		}

		std::set<Value*> regs;
		for (auto* s : e.possibleArgStores)
		{
			Value* r = s->getPointerOperand();
			if (_config->isRegister(r))
			{
				regs.insert(r);
			}
		}

		std::set<Value*> intersect;
		std::set_intersection(
				commonRegs.begin(),
				commonRegs.end(),
				regs.begin(),
				regs.end(),
				std::inserter(intersect, intersect.begin()));
		commonRegs = std::move(intersect);
	}

	// If common contains r3, then it should also contain r2, r1, and r0.
	// Example for MIPS: if contains a2, it should a1 and a0.
	//
	static std::vector<std::string> regNames;
	if (regNames.empty())
	{
		if (_config->getConfig().architecture.isMipsOrPic32())
		{
			if (_config->getConfig().tools.isPspGcc())
			{
				regNames = {"a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3"};
			}
			else
			{
				regNames = {"a0", "a1", "a2", "a3"};
			}
		}
		else if (_config->getConfig().architecture.isArmOrThumb())
		{
			regNames = {"r0", "r1", "r2", "r3"};
		}
		else if (_config->getConfig().architecture.isPpc())
		{
			regNames = {"r3", "r4", "r5", "r6", "r7", "r8", "r9"};
		}
	}
	for (auto it = regNames.rbegin(); it != regNames.rend(); ++it)
	{
		auto* r = _config->getLlvmRegister(*it);
		if (commonRegs.count(r))
		{
			++it;
			while (it != regNames.rend())
			{
				r = _config->getLlvmRegister(*it);
				commonRegs.insert(r);
				++it;
			}
			break;
		}
	}

	for (auto& e : calls)
	{
		auto it = e.possibleArgStores.begin();
		for ( ; it != e.possibleArgStores.end(); )
		{
			Value* r = (*it)->getPointerOperand();
			if (_config->isRegister(r)
					&& commonRegs.find(r) == commonRegs.end())
			{
				it = e.possibleArgStores.erase(it);
			}
			else
			{
				++it;
			}
		}
	}
}

void DataFlowEntry::callsFilterSameNumberOfStacks()
{
	if (calls.empty())
	{
		return;
	}

	std::size_t loads = 0;
	for (auto* l : argLoads)
	{
		if (_config->isStackVariable(l->getPointerOperand()))
		{
			++loads;
		}
	}

	std::size_t stacks = std::numeric_limits<std::size_t>::max();
	for (auto& ce : calls)
	{
		std::size_t ss = 0;
		for (auto* s : ce.possibleArgStores)
		{
			if (_config->isStackVariable(s->getPointerOperand()))
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
		auto it = ce.possibleArgStores.begin();
		while (it != ce.possibleArgStores.end())
		{
			auto* s = *it;
			if (!_config->isStackVariable(s->getPointerOperand()))
			{
				++it;
				continue;
			}

			++cntr;
			if (cntr > stacks)
			{
				it = ce.possibleArgStores.erase(it);
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

void DataFlowEntry::applyToIrOrdinary()
{
	if (Function* fnc = getFunction())
	{
		if (fnc->arg_size() > 0)
		{
			return;
		}

		std::map<llvm::CallInst*, std::vector<llvm::Value*>> calls2vals;
		for (auto& e : calls)
		{
			std::vector<Value*> loads;
			auto* call = e.call;
			for (auto* s : e.possibleArgStores)
			{
				auto fIt = specialArgStorage.find(loads.size());
				while (fIt != specialArgStorage.end())
				{
					auto* sl = new LoadInst(fIt->second, "", call);
					loads.push_back(sl);
					fIt = specialArgStorage.find(loads.size());
				}

				auto* l = new LoadInst(s->getPointerOperand(), "", call);
				loads.push_back(l);
			}

			calls2vals[call] = loads;
		}

		llvm::Value* retVal = nullptr;
		std::map<ReturnInst*, Value*> rets2vals;
		if (_config->getConfig().architecture.isX86())
		{
			if (retType->isFloatingPointTy())
			{
				retVal = _config->getLlvmRegister("st0");
			}
			else if (_config->getConfig().architecture.isX86_32())
			{
				retVal = _config->getLlvmRegister("eax");
			}
			else if (_config->getConfig().architecture.isX86_64())
			{
				retVal = _config->getLlvmRegister("rax");
			}
		}
		else if (_config->getConfig().architecture.isMipsOrPic32())
		{
			retVal = _config->getLlvmRegister("v0");
		}
		else if (_config->getConfig().architecture.isArmOrThumb())
		{
			retVal = _config->getLlvmRegister("r0");
		}
		else if (_config->getConfig().architecture.isPpc())
		{
			retVal = _config->getLlvmRegister("r3");
		}
		if (retVal)
		{
			for (auto& e : retStores)
			{
				auto* l = new LoadInst(retVal, "", e.ret);
				rets2vals[e.ret] = l;
			}
		}

		std::vector<llvm::Value*> argStores;
		for (LoadInst* l : argLoads)
		{
			auto fIt = specialArgStorage.find(argStores.size());
			while (fIt != specialArgStorage.end())
			{
				argStores.push_back(fIt->second);
				fIt = specialArgStorage.find(argStores.size());
			}

			argStores.push_back(l->getPointerOperand());
		}

		static std::vector<std::string> ppcNames =
				{"r3", "r4", "r5", "r6", "r7", "r8", "r9"};
		static std::vector<std::string> armNames =
				{"r0", "r1", "r2", "r3"};
		static std::vector<std::string> mipsNames =
				{"a0", "a1", "a2", "a3"};
		if (_config->getConfig().tools.isPspGcc())
		{
			mipsNames = {"a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3"};
		}
		for (auto& p : calls2vals)
		{
			retdec::utils::Maybe<int> stackOff;
			if (_config->getConfig().architecture.isX86())
			{
				if (!p.second.empty())
				{
					auto* l = cast<LoadInst>(p.second.back());
					if (_config->isStackVariable(l->getPointerOperand()))
					{
						stackOff = _config->getStackVariableOffset(l->getPointerOperand());
						stackOff = stackOff + 4;
					}
				}

				if (stackOff.isUndefined())
				{
					AsmInstruction ai(p.first);
					while (ai.isValid())
					{
						for (auto& i : ai)
						{
							if (auto* s = dyn_cast<StoreInst>(&i))
							{
								if (_config->isStackVariable(s->getPointerOperand()))
								{
									stackOff = _config->getStackVariableOffset(s->getPointerOperand());
									break;
								}
							}
						}
						if (stackOff.isDefined())
						{
							break;
						}
						ai = ai.getPrev();
					}
				}
			}

			std::size_t idx = 0;
			for (auto* t : argTypes)
			{
				(void) t;
				if (p.second.size() <= idx)
				{
					if (_config->getConfig().architecture.isArmOrThumb())
					{
						if (idx < armNames.size())
						{
							auto* r = _config->getLlvmRegister(armNames[idx]);
							auto* l = new LoadInst(r, "", p.first);
							p.second.push_back(l);
						}
					}
					else if (_config->getConfig().architecture.isMipsOrPic32())
					{
						if (idx < mipsNames.size())
						{
							auto* r = _config->getLlvmRegister(mipsNames[idx]);
							auto* l = new LoadInst(r, "", p.first);
							p.second.push_back(l);
						}
					}
					else if (_config->getConfig().architecture.isPpc())
					{
						if (idx < ppcNames.size())
						{
							auto* r = _config->getLlvmRegister(ppcNames[idx]);
							auto* l = new LoadInst(r, "", p.first);
							p.second.push_back(l);
						}
					}
					else if (_config->getConfig().architecture.isX86()
							&& stackOff.isDefined())
					{
						auto* s = _config->getLlvmStackVariable(p.first->getFunction(), stackOff);
						if (s)
						{
							auto* l = new LoadInst(s, "", p.first);
							p.second.push_back(l);
							stackOff = stackOff + 4;
						}
						else
						{
							stackOff.setUndefined();
						}
					}
				}
				++idx;
			}
		}

		auto* oldType = fnc->getType();
		IrModifier irm(_module, _config);
		auto* newFnc = irm.modifyFunction(
				fnc,
				retType,
				argTypes,
				isVarArg,
				rets2vals,
				calls2vals,
				retVal,
				argStores,
				argNames).first;

		LOG << "modify fnc: " << newFnc->getName().str() << " = "
				<< llvmObjToString(oldType) << " -> "
				<< llvmObjToString(newFnc->getType()) << std::endl;

		called = newFnc;
	}
	else
	{
		for (auto& e : calls)
		{
			auto* call = e.call;
			LOG << "\tmodify call: " << llvmObjToString(call) << std::endl;

			std::vector<Value*> loads;
			for (auto* s : e.possibleArgStores)
			{
				auto* l = new LoadInst(s->getPointerOperand(), "", call);
				loads.push_back(l);
				LOG << "\t\t" << llvmObjToString(l) << std::endl;
			}

			auto* ret = fnc ? fnc->getReturnType() : call->getType();
			IrModifier::modifyCallInst(call, ret, loads);
		}
	}
}

void DataFlowEntry::applyToIrVariadic()
{
	std::vector<std::string> ppcNames =
			{"r3", "r4", "r5", "r6", "r7", "r8", "r9"};
	std::vector<std::string> armNames =
			{"r0", "r1", "r2", "r3"};
	std::vector<std::string> mipsNames =
			{"a0", "a1", "a2", "a3"};
	if (_config->getConfig().tools.isPspGcc())
	{
		mipsNames = {"a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3"};
	}

	std::vector<std::string> mipsFpNames =
			{"fd12", "fd13", "fd14", "fd15", "fd16", "fd17", "fd18", "fd19", "fd20"};

	llvm::Value* retVal = nullptr;
	std::map<ReturnInst*, Value*> rets2vals;
	std::vector<llvm::Value*> argStores;
	std::map<llvm::CallInst*, std::vector<llvm::Value*>> calls2vals;

	for (CallEntry& ce : calls)
	{
		auto* fnc = ce.call->getFunction();
		auto* calledFnc = ce.call->getCalledFunction();

		LOG << llvmObjToString(ce.call) << std::endl;
		LOG << "\tformat : " << ce.formatStr << std::endl;

		// get lowest stack offset
		//
		int stackOff = std::numeric_limits<int>::max();
		for (StoreInst* s : ce.possibleArgStores)
		{
			if (_config->isStackVariable(s->getPointerOperand()))
			{
				auto so = _config->getStackVariableOffset(s->getPointerOperand());
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

			if (_config->getConfig().architecture.isX86())
			{
				auto* st = _config->getLlvmStackVariable(fnc, off);
				if (st)
				{
					args.push_back(st);
				}

				off += sz;
			}
			else if (_config->getConfig().architecture.isPpc())
			{
				if (aIdx < ppcNames.size())
				{
					auto* r = _module->getNamedGlobal(ppcNames[aIdx]);
					if (r)
					{
						args.push_back(r);
					}
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
			else if (_config->getConfig().architecture.isArmOrThumb())
			{
				if (aIdx < armNames.size())
				{
					auto* r = _module->getNamedGlobal(armNames[aIdx]);
					if (r)
					{
						args.push_back(r);
					}

					if (sz > 4)
					{
						++aIdx;
					}
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
			else if (_config->getConfig().architecture.isPic32())
			{
				if (aIdx < mipsNames.size())
				{
					auto* r = _module->getNamedGlobal(mipsNames[aIdx]);
					if (r)
					{
						args.push_back(r);
					}
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
			else if (_config->getConfig().architecture.isMips())
			{
				bool useStack = false;
				if (t->isFloatingPointTy())
				{
					--aIdx;

					if (faIdx < mipsFpNames.size())
					{
						auto* r = _module->getNamedGlobal(mipsFpNames[faIdx]);
						if (r)
						{
							args.push_back(r);
						}

						if (sz > 4)
						{
							++faIdx;
						}
					}
					else
					{
						useStack = true;
					}

					++faIdx;
				}
				else
				{
					if (aIdx < mipsNames.size())
					{
						auto* r = _module->getNamedGlobal(mipsNames[aIdx]);
						if (r)
						{
							args.push_back(r);
						}
					}
					else
					{
						useStack = true;
					}
				}

				if (useStack)
				{
					auto* st = _config->getLlvmStackVariable(fnc, off);
					if (st)
					{
						args.push_back(st);
					}

					off += sz;
				}
			}

			++aIdx;
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
			calls2vals[ce.call] = loads;
		}
	}

	if (_config->getConfig().architecture.isX86())
	{
		if (retType->isFloatingPointTy())
		{
			retVal = _config->getLlvmRegister("st0");
		}
		else if (_config->getConfig().architecture.isX86_32())
		{
			retVal = _config->getLlvmRegister("eax");
		}
		else if (_config->getConfig().architecture.isX86_64())
		{
			retVal = _config->getLlvmRegister("rax");
		}
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		retVal = _config->getLlvmRegister("v0");
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		retVal = _config->getLlvmRegister("r0");
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		retVal = _config->getLlvmRegister("r3");
	}
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
			calls2vals,
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
	if (!typeSet)
	{
		setReturnType();
		setArgumentTypes();
		typeSet = true;
	}
}

void DataFlowEntry::setReturnType()
{
	llvm::Value* retVal = nullptr;
	if (_config->getConfig().architecture.isX86())
	{
		bool hasEax = false;
		bool hasRax = false;
		bool hasSt0 = false;
		for (auto& re : retStores)
		{
			for (StoreInst* s : re.possibleRetStores)
			{
				if (s->getPointerOperand()->getName() == "eax")
				{
					hasEax = true;
					break;
				}
				else if (s->getPointerOperand()->getName() == "rax")
				{
					hasRax = true;
					break;
				}
				else if (s->getPointerOperand()->getName() == "st0")
				{
					hasSt0 = true;
				}
			}
		}
		if (!hasEax && !hasRax && hasSt0)
		{
			retVal = _config->getLlvmRegister("st0");
		}
		else if (_config->getLlvmRegister("rax"))
		{
			retVal = _config->getLlvmRegister("rax");
		}
		else
		{
			retVal = _config->getLlvmRegister("eax");
		}
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		retVal = _config->getLlvmRegister("v0");
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		retVal = _config->getLlvmRegister("r0");
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		retVal = _config->getLlvmRegister("r3");
	}

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
				argLoads.size(),
				Abi::getDefaultType(_module));
	}
	else
	{
		CallEntry* ce = &calls.front();
		for (auto& c : calls)
		{
			if (!c.possibleArgStores.empty())
			{
				ce = &c;
				break;
			}
		}

		argTypes.insert(
				argTypes.end(),
				ce->possibleArgStores.size(),
				Abi::getDefaultType(_module));
	}
}

} // namespace bin2llvmir
} // namespace retdec
