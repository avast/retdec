/**
 * @file src/bin2llvmir/analyses/ctor_dtor.cpp
 * @brief Constructor and destructor detection analysis.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/analyses/ctor_dtor.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

void CtorDtor::runOnModule(llvm::Module* m, Config* c, FileImage* i)
{
	module = m;
	config = c;
	image = i;

	findPossibleCtorsDtors();

	for (auto& f : possibleCtorsDtors)
	{
		analyseFunction(f);
	}

	propagateCtorDtor();
}

CtorDtor::FunctionToInfo& CtorDtor::getResults()
{
	return function2info;
}

/**
 * Collects all stores to global variables at vtable addresses.
 * Collects functions where these stores are.
 */
void CtorDtor::findPossibleCtorsDtors()
{
	LOG << "\n*** findPossibleCtorsDtors()" << std::endl;

	for (Function& F : *module)
	{
		if (F.getName() == "main")
		{
			continue;
		}
		LOG << "[FUNCTION] : " << F.getName().str() << std::endl;

		for (auto it = inst_begin(&F), eIt = inst_end(&F); it != eIt; ++it)
		{
			StoreInst *store = dyn_cast<StoreInst>(&*it);
			if (store == nullptr)
				continue;

			retdec::utils::Address addr;
			const Value* v = llvm_utils::skipCasts(store->getValueOperand());
			if (auto* gv = dyn_cast_or_null<GlobalVariable>(v))
			{
				addr = config->getGlobalAddress(gv);
			}

			auto* vt = image->getRtti().getVtable(addr);
			if (vt)
			{
				LOG << "\t" << llvmObjToString(store)
					<< " -> " << vt->vtableAddress << std::endl;

				stores2vtables[store] = vt;
				possibleCtorsDtors.insert(&F);
			}
		}
	}
}

void CtorDtor::analyseFunction(Function* fnc)
{
	LOG << "\n*** analyseFunction() : " << fnc->getName().str() << std::endl;

	auto forward = analyseFunctionForward(fnc);
	auto backward = analyseFunctionBackward(fnc);

	CtorDtor::FunctionInfo result;

	result.ctor = !forward.superMethods.empty();
	result.dtor = !backward.superMethods.empty();

	if (!result.ctor && !result.dtor)
	{
		result.ctor = result.dtor = !forward.vftableStores.empty()
				|| !backward.vftableStores.empty();
	}

	if (result.ctor)
	{
		result.superMethods = forward.superMethods;
		result.vftableStores = forward.vftableStores;
	}
	if (result.dtor && result.superMethods.empty())
	{
		result.superMethods = backward.superMethods;
	}
	if (result.dtor && result.vftableStores.empty())
	{
		result.vftableStores = backward.vftableStores;
	}

	for (auto* call : result.superMethods)
	{
		int offset = -1;

		// Should run only if MSVC++ or GCC on PE.

		if (auto* store = findPreviousStoreToECX(call))
			offset = getOffset(store->getValueOperand());

		if (offset < 0 && call->getNumArgOperands() > 0)
			offset = getOffset(call->getArgOperand(0));

		if (offset < 0)
			offset = 0;

		result.superMethodOffsets.push_back(offset);
	}

	for (auto& store : result.vftableStores)
	{
		result.vftableOffsets.push_back(
				getOffset(store.first->getPointerOperand()));
	}

	LOG << "====> ctor = " << result.ctor << std::endl;
	LOG << "====> dtor = " << result.dtor << std::endl;

	function2info[fnc] = result;
}

CtorDtor::FunctionInfo CtorDtor::analyseFunctionForward(Function* fnc)
{
	LOG << "\n*** analyseFunctionForward() : "
		<< fnc->getName().str() << std::endl;

	if (fnc->getBasicBlockList().empty())
		return CtorDtor::FunctionInfo();

	auto& bb = fnc->front();
	return analyseFunctionCommon<BasicBlock::iterator>( bb.begin(), bb.end() );
}

CtorDtor::FunctionInfo CtorDtor::analyseFunctionBackward(Function* fnc)
{
	LOG << "\n*** analyseFunctionBackward() : "
		<< fnc->getName().str() << std::endl;

	if (fnc->getBasicBlockList().empty())
		return CtorDtor::FunctionInfo();

	auto& bb = fnc->back();
	return analyseFunctionCommon<BasicBlock::reverse_iterator>(
			bb.rbegin(),
			bb.rend());
}

int CtorDtor::getOffset(Value* ecxStoreOp)
{
	LOG << "\n*** getOffset() : " << llvmObjToString(ecxStoreOp) << std::endl;

	ecxStoreOp = llvm_utils::skipCasts(ecxStoreOp);
	LOG << "\tdef @ " << llvmObjToString(ecxStoreOp) << std::endl;

	int offset = 0;
	if (isa<Instruction>(ecxStoreOp))
	{
		const Instruction *inst = cast<Instruction>(ecxStoreOp);
		if (inst->getOpcode() == Instruction::Add
				&& isa<ConstantInt>(inst->getOperand(1)))
		{
			int op = cast<ConstantInt>(inst->getOperand(1))->getZExtValue();
			offset = op + getOffset(inst->getOperand(0));
		}
		else if (inst->getOpcode() == Instruction::Sub
				&& isa<ConstantInt>(inst->getOperand(1)))
		{
			int op = cast<ConstantInt>(inst->getOperand(1))->getZExtValue();
			offset = -op + getOffset(inst->getOperand(0));
		}
	}

	LOG << "\t offset = " << offset << std::endl;
	return offset;
}

/**
 * Find store to gpr1 (ecx) before @p inst.
 * @param inst Instruction to find store before.
 * @return Found store, or nullptr.
 */
StoreInst* CtorDtor::findPreviousStoreToECX(Instruction* inst)
{
	// TODO
	return nullptr;
}

/**
 * Sometimes function analysis can not decide, if function is ctor or dtor.
 * This is typical for base classes' ctors/dtors, which are not calling
 * super methods. However, we can do a bottom-up propagation: if we know some
 * method is ctor/dtor and it is calling some super method, we can say if
 * the super method is ctor/dtor.
 */
void CtorDtor::propagateCtorDtor()
{
	LOG << "\n*** propagateCtorDtor() : " << std::endl;

	bool changed = true;
	while (changed)
	{
		changed = false;

		for (auto& fi : function2info)
		{
			auto& thisInfo = fi.second;

			for (auto* call : thisInfo.superMethods)
			{
				auto* superFnc = call->getCalledFunction();
				auto fIt = function2info.find(superFnc);
				assert(fIt != function2info.end());
				auto& superInfo = fIt->second;

				if (thisInfo.ctor && !thisInfo.dtor
						&& superInfo.ctor && superInfo.dtor)
				{
					superInfo.ctor = true;
					superInfo.dtor = false;
					changed = true;

					LOG << "\t" << fIt->first->getName().str()
						<< " -> is ctor" << std::endl;
				}
				else if (!thisInfo.ctor && thisInfo.dtor
						&& superInfo.ctor && superInfo.dtor)
				{
					superInfo.ctor = false;
					superInfo.dtor = true;
					changed = true;

					LOG << "\t" << fIt->first->getName().str()
						<< " -> is dtor" << std::endl;
				}
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
