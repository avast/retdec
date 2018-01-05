/**
 * @file src/bin2llvmir/optimizations/ctor_dtor/ctor_dtor.cpp
 * @brief Constructor and destructor detection analysis.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/ctor_dtor/ctor_dtor.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::llvm_support;
using namespace llvm;

#define debug_enabled false

/**
* Helper function, meybe move to utils.
*/
static const Value* goThroughCasts(const Value *v)
{
	if (isa<CastInst>(v))
	{
		return goThroughCasts(cast<CastInst>(v)->getOperand(0));
	}
	else if (isa<ConstantExpr>(v) && cast<ConstantExpr>(v)->isCast())
	{
		return goThroughCasts(cast<ConstantExpr>(v)->getOperand(0));
	}
	else if (isa<InsertValueInst>(v))
	{
		const InsertValueInst *ins = cast<InsertValueInst>(v);

		// skip aggregate value and inserted value operands,
		// all other (hence index) operands must be zero
		//
		bool allZeros = true;
		for (unsigned i = 2; i < ins->getNumOperands(); i++)
		{
			Value *op = ins->getOperand(i);

			if (!isa<ConstantInt>(op) || !cast<ConstantInt>(op)->isNullValue())
			{
				allZeros = false;
				break;
			}
		}

		if (allZeros)
		{
			return goThroughCasts(ins->getInsertedValueOperand());
		}
	}

	return v;
}

namespace retdec {
namespace bin2llvmir {

char CtorDtor::ID = 0;

static RegisterPass<CtorDtor> RegisterPass(
		"ctor-dtor",
		"C++ constructor and destructor optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

CtorDtor::CtorDtor() :
		ModulePass(ID)
{
}

void CtorDtor::getAnalysisUsage(AnalysisUsage &AU) const
{
	AU.setPreservesAll();
	AU.addRequired<VtableAnalysis>();
}

bool CtorDtor::runOnModule(Module& M)
{
	module = &M;

	if (!ConfigProvider::getConfig(module, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	findPossibleCtorsDtors();

	for (auto& f : possibleCtorsDtors)
	{
		analyseFunction(f);
	}

	propagateCtorDtor();

	for (auto& p : stores2vtables)
	{
		replaceVtablesPointersInStores(p.first, p.second);
	}

	return false;
}

CtorDtor::FunctionToInfo& CtorDtor::getResults()
{
	return function2info;
}

void CtorDtor::findPossibleCtorsDtors()
{
	LOG << "\n*** findPossibleCtorsDtors()" << std::endl;

	auto& VA = getAnalysis<VtableAnalysis>();

	for (auto &F : *module)
	{
		if (F.isDeclaration())
			continue;

		if (F.getName() == "main")
			continue;

		LOG << "[FUNCTION] : " << F.getName().str() << std::endl;

		for (auto &B : F)
		for (Instruction &I : B)
		{
			StoreInst *store = dyn_cast<StoreInst>(&I);
			if (store == nullptr)
				continue;

			retdec::utils::Address addr;
			const Value* v = goThroughCasts(store->getValueOperand());
			if (auto* ci = dyn_cast<ConstantInt>(store->getValueOperand()))
			{
				addr = ci->getZExtValue();
			}
			else if (auto* gv = dyn_cast_or_null<GlobalVariable>(v))
			{
				addr = config->getGlobalAddress(gv);
			}

			auto* vt = VA.getVtableOnAddress(addr);
			if (vt)
			{
				LOG << "\t" << llvmObjToString(store)
					<< " -> " << vt->getName() << std::endl;

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

void CtorDtor::replaceVtablesPointersInStores(StoreInst* store, Vtable* vtable)
{
	auto* cast = convertConstantToType(
			vtable->global,
			store->getValueOperand()->getType());
	StoreInst *store2 = new StoreInst(cast, store->getPointerOperand(), store);
	store->replaceAllUsesWith(store2);
	store->eraseFromParent();
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

int CtorDtor::getOffset(const Value* ecxStoreOp)
{
	LOG << "\n*** getOffset() : " << llvmObjToString(ecxStoreOp) << std::endl;

	ecxStoreOp = goThroughCasts(ecxStoreOp);
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
 *
 * TODO: maybe I could move this to RDA? would it make sense? would it work?
 */
const StoreInst* CtorDtor::findPreviousStoreToECX(const Instruction* inst)
{
	LOG << "\n*** findPreviousStoreToECX() : "
		<< llvmObjToString(inst) << std::endl;

	if (inst->getParent()->empty())
		return nullptr;

	const Value *ecx = module->getGlobalVariable("gpr1", true);

	while (inst != &inst->getParent()->front())
	{
		inst = inst->getPrevNode();
		if (isa<StoreInst>(inst)
				&& cast<StoreInst>(inst)->getPointerOperand() == ecx)
		{
			LOG << "\tfound = " << llvmObjToString(inst) << "\n";
			return cast<StoreInst>(inst);
		}
	}
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
