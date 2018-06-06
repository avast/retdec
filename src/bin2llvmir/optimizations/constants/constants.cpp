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
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
const bool debug_enabled = false;
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

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

bool ConstantsAnalysis::runOnModule(Module &M)
{
	m_module = &M;
	objf = FileImageProvider::getFileImage(&M);
	config = ConfigProvider::getConfig(&M);
	auto* abi = AbiProvider::getAbi(&M);
	dbgf = DebugFormatProvider::getDebugFormat(&M);

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(M, abi);

	for (Function& f : M.getFunctionList())
	for (inst_iterator I = inst_begin(&f), E = inst_end(&f); I != E;)
	{
		Instruction& i = *I;
		++I;

		if (StoreInst *store = dyn_cast<StoreInst>(&i))
		{
			if (AsmInstruction::isLlvmToAsmInstruction(store))
			{
				continue;
			}

			checkForGlobalInInstruction(RDA, store, store->getValueOperand(), true);

			if (isa<GlobalVariable>(store->getPointerOperand()))
			{
				continue;
			}

			checkForGlobalInInstruction(RDA, store, store->getPointerOperand());
		}
		else if (auto* load = dyn_cast<LoadInst>(&i))
		{
			if (isa<GlobalVariable>(load->getPointerOperand()))
			{
				continue;
			}

			checkForGlobalInInstruction(RDA, load, load->getPointerOperand());
		}
	}

	tagFunctionsWithUsedCryptoGlobals();

	return false;
}

void ConstantsAnalysis::checkForGlobalInInstruction(
		ReachingDefinitionsAnalysis& RDA,
		Instruction* inst,
		Value* val,
		bool storeValue)
{
	LOG << llvmObjToString(inst) << std::endl;

	if (val->getType()->isIntegerTy(1)
			|| (val->getType()->isPointerTy()
			&& val->getType()->getPointerElementType()->isIntegerTy(1)))
	{
		return;
	}

	SymbolicTree root(RDA, val);
	root.simplifyNode();

	LOG << root << std::endl;

	auto* max = root.getMaxIntValue();
	auto* maxC = max ? dyn_cast_or_null<ConstantInt>(max->value) : nullptr;
	Instruction* userI = max ? dyn_cast_or_null<Instruction>(max->user) : nullptr;

	if (max && maxC && maxC->getZExtValue() != 0)
	if (userI || max == &root)
	if (objf->getImage()->hasDataOnAddress(maxC->getZExtValue()))
	{
		IrModifier irm(m_module, config);
		auto* ngv = irm.getGlobalVariable(
				objf,
				dbgf,
				maxC->getZExtValue(),
				storeValue);

		if (ngv)
		{
			if (max == &root)
			{
				auto* conv = IrModifier::convertConstantToType(ngv, val->getType());
				inst->replaceUsesOfWith(val, conv);
				return;
			}
			else if (userI)
			{
				auto* conv = IrModifier::convertConstantToType(ngv, maxC->getType());
				userI->replaceUsesOfWith(maxC, conv);
				return;
			}
		}
	}

	auto* gv = dyn_cast<GlobalVariable>(root.value);
	if (isa<LoadInst>(inst) && gv && root.ops.size() <= 1)
	{
		auto* conv = IrModifier::convertConstantToType(gv, val->getType());
		inst->replaceUsesOfWith(val, conv);
		return;
	}
}

void ConstantsAnalysis::tagFunctionsWithUsedCryptoGlobals()
{
	for (GlobalVariable& lgv : m_module->getGlobalList())
	{
		auto* cgv = config->getConfigGlobalVariable(&lgv);
		if (cgv == nullptr || cgv->getCryptoDescription().empty())
		{
			continue;
		}

		for (auto* user : lgv.users())
		{
			if (auto* i = dyn_cast_or_null<Instruction>(user))
			{
				if (auto* cf = config->getConfigFunction(i->getFunction()))
				{
					cf->usedCryptoConstants.insert(cgv->getCryptoDescription());
				}
			}
			else if (auto* e = dyn_cast_or_null<ConstantExpr>(user))
			{
				for (auto* u : e->users())
				{
					if (auto* i = dyn_cast_or_null<Instruction>(u))
					{
						if (auto* cf = config->getConfigFunction(i->getFunction()))
						{
							cf->usedCryptoConstants.insert(cgv->getCryptoDescription());
						}
					}
				}
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
