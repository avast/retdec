/**
* @file src/bin2llvmir/optimizations/constants/constants.cpp
* @brief Composite type reconstruction analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/string.h"
#include "retdec/utils/time.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/optimizations/constants/constants.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/global_var.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ConstantsAnalysis::ID = 0;

static RegisterPass<ConstantsAnalysis> X(
		"constants",
		"Constants optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ConstantsAnalysis::ConstantsAnalysis() :
		ModulePass(ID)
{

}

void ConstantsAnalysis::getAnalysisUsage(AnalysisUsage &AU) const
{

}

bool ConstantsAnalysis::runOnModule(Module &M)
{
	LOG << "\n[BEGIN] ======================== ConstantsAnalysis:\n" << std::endl;

	if (!FileImageProvider::getFileImage(&M, objf))
	{
		LOG << "[ABORT] object file is not available\n";
		return false;
	}
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}
	dbgf = DebugFormatProvider::getDebugFormat(&M);

	m_module = &M;

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(M, config);

	setPic32GpValue(RDA);

	for (auto &F : M.getFunctionList())
	for (auto &B : F)
	for (auto &I : B)
	{
		if (StoreInst *store = dyn_cast<StoreInst>(&I))
		{
			if (AsmInstruction::isLlvmToAsmInstruction(store))
			{
				continue;
			}

			if (store->getPointerOperand()->getType()->isPointerTy() &&
				store->getPointerOperand()->getType()->getPointerElementType()->isIntegerTy(1))
			{
				continue;
			}

			if (!isa<GlobalVariable>(store->getPointerOperand()))
			{
				checkForGlobalInInstruction(RDA, store, store->getPointerOperand());
			}
			checkForGlobalInInstruction(RDA, store, store->getValueOperand(), true);
		}
		else if (CallInst *call = dyn_cast<CallInst>(&I))
		{
			unsigned args = call->getNumArgOperands();
			for (unsigned i=0; i<args; ++i)
			{
				checkForGlobalInInstruction(RDA, &I, call->getArgOperand(i));
			}
		}
		else if (auto* load = dyn_cast<LoadInst>(&I))
		{
			if (load->getPointerOperand()->getType()->isPointerTy() &&
				load->getPointerOperand()->getType()->getPointerElementType()->isIntegerTy(1))
				continue;

			if (isa<GlobalVariable>(load->getPointerOperand()))
				continue;

			checkForGlobalInInstruction(RDA, load, load->getPointerOperand());
		}
	}

	tagFunctionsWithUsedCryptoGlobals();

	LOG << "\n[END]   ======================== ConstantsAnalysis:\n";
	return false;
}

void ConstantsAnalysis::checkForGlobalInInstruction(
		ReachingDefinitionsAnalysis& RDA,
		Instruction* inst,
		Value* val,
		bool storeValue)
{
	LOG << llvmObjToString(inst) << std::endl;

	// TODO: maybe allow only arch bit sizes? (e.g. 32/64)
	if (val->getType()->isIntegerTy(1))
	{
		return;
	}

	SymbolicTree root(RDA, val);
	LOG << root << std::endl;
	if (!root.isConstructedSuccessfully())
	{
		return;
	}
	root.simplifyNode(config);
	LOG << root << std::endl;

	auto* max = root.getMaxIntValue();
	auto* maxC = max ? dyn_cast_or_null<ConstantInt>(max->value) : nullptr;
	Instruction* userI = max ? dyn_cast_or_null<Instruction>(max->user) : nullptr;

	if (max && maxC)
	if (userI || max == &root) // TODO: see comment in store
	if (objf->getImage()->hasDataOnAddress(maxC->getZExtValue()))
	if (maxC->getZExtValue() != 0)
	{
		auto* ngv = getGlobalVariable(
				m_module,
				config,
				objf,
				dbgf,
				maxC->getZExtValue(),
				storeValue);

		if (ngv)
		{
			if (max == &root)
			{
				auto* conv = convertConstantToType(ngv, val->getType());
				inst->replaceUsesOfWith(val, conv);
				return;
			}
			else if (userI)
			{
				auto* conv = convertConstantToType(ngv, maxC->getType());
				userI->replaceUsesOfWith(maxC, conv);
				return;
			}
		}
	}

	auto* gv = dyn_cast<GlobalVariable>(root.value);
	if (isa<LoadInst>(inst) && gv && root.ops.size() <= 1)
	{
		auto* conv = convertConstantToType(gv, val->getType());
		inst->replaceUsesOfWith(val, conv);
		return;
	}
}

void ConstantsAnalysis::tagFunctionsWithUsedCryptoGlobals()
{
	for (auto& lgv : m_module->getGlobalList())
	{
		auto* cgv = config->getConfigGlobalVariable(&lgv);
		if (cgv == nullptr || cgv->getCryptoDescription().empty())
		{
			continue;
		}

		for (auto* user : lgv.users())
		{
			auto pfs = getParentFuncsFor(user);
			for (auto* f : pfs)
			{
				auto* cfnc = config->getConfigFunction(f);
				if (cfnc == nullptr)
				{
					continue;
				}
				cfnc->usedCryptoConstants.insert(cgv->getCryptoDescription());
			}
		}
	}
}

void ConstantsAnalysis::setPic32GpValue(ReachingDefinitionsAnalysis& RDA)
{
	if (config == nullptr || !config->isPic32())
	{
		return;
	}

	for (auto& f : m_module->getFunctionList())
	{
		GlobalVariable* gp = nullptr;
		ConstantInt* lastVal = nullptr;
		for (inst_iterator i = inst_begin(f), e = inst_end(f); i != e; ++i)
		{
			if (auto* s = dyn_cast<StoreInst>(&(*i)))
			{
				auto* r = s->getPointerOperand();
				auto* v = s->getValueOperand();

				if (!config->isRegister(r) || r->getName() != "gp")
				{
					continue;
				}

				SymbolicTree root(RDA, v);
				if (!root.isConstructedSuccessfully())
				{
					continue;
				}
				root.simplifyNode(config);
				auto* ci = dyn_cast_or_null<ConstantInt>(root.value);
				if (ci == nullptr)
				{
					continue;
				}
				lastVal = ci;
				gp = dyn_cast<GlobalVariable>(r);
			}
		}

		if (gp && lastVal)
		{
			gp->setInitializer(lastVal);
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
