/**
* @file src/bin2llvmir/optimizations/local_vars/local_vars.cpp
* @brief Register localization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/local_vars/local_vars.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/bin2llvmir/utils/instruction.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

char LocalVars::ID = 0;

static RegisterPass<LocalVars> X(
		"local-vars",
		"Register localization optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

LocalVars::LocalVars() :
		ModulePass(ID)
{

}

void LocalVars::getAnalysisUsage(AnalysisUsage &AU) const
{

}

/**
 * @return @c True if al least one instruction was (un)volatilized.
 *         @c False otherwise.
 */
bool LocalVars::runOnModule(Module& M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(M, config);

	for (auto &F : M.getFunctionList())
	for (auto &B : F)
	for (auto &I : B)
	{
		if (CallInst* call = dyn_cast<CallInst>(&I))
		{
			if (isIndirectCall(call))
			{
				continue;
			}

			for (auto& a : call->arg_operands())
			{
				auto* aa = dyn_cast_or_null<Instruction>(skipCasts(a));
				if (aa == nullptr)
				{
					continue;
				}
				auto* use = RDA.getUse(aa);
				if (use == nullptr || use->defs.size() != 1)
				{
					continue;
				}
				auto* d = *use->defs.begin();
				if (a->getType()->isFloatingPointTy()
						&& !d->getSource()->getType()->isFloatingPointTy())
				{
					localizeDefinition(d);
				}
				else if (config->isRegister(d->getSource()))
				{
					localizeDefinition(d);
				}
			}
		}
		else if (ReturnInst* ret = dyn_cast<ReturnInst>(&I))
		{
			auto* a = skipCasts(ret->getReturnValue());
			if (a == nullptr)
				continue;
			if (auto* l = dyn_cast<LoadInst>(a))
			{
				auto* use = RDA.getUse(l);
				if (use == nullptr || use->defs.size() != 1)
				{
					continue;
				}
				auto* d = *use->defs.begin();
				if (!config->isRegister(d->getSource()))
				{
					continue;
				}
				localizeDefinition(d);
			}
		}
		else if (StoreInst* s = dyn_cast<StoreInst>(&I))
		{
			if (!config->isRegister(s->getPointerOperand()))
			{
				continue;
			}

			auto* d = RDA.getDef(s);
			if (d == nullptr)
			{
				continue;
			}

			auto* vo = skipCasts(s->getValueOperand());
			if (isa<CallInst>(vo))
			{
				localizeDefinition(d);
			}
			else if (isa<Argument>(vo))
			{
				localizeDefinition(d);
			}
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
