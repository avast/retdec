/**
* @file src/bin2llvmir/optimizations/local_vars/local_vars.cpp
* @brief Register localization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/local_vars/local_vars.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool canBeLocalized(
		const Definition* def,
		std::set<llvm::Instruction*>& uses)
{
	uses.clear();
	for (auto* u : def->uses)
	{
		if (u->defs.size() > 1)
		{
			return false;
		}
		uses.insert(u->use);
	}
	return !def->uses.empty();
}

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

/**
 * @return @c True if al least one instruction was (un)volatilized.
 *         @c False otherwise.
 */
bool LocalVars::runOnModule(Module& M)
{
	Abi* abi = nullptr;
	if (!AbiProvider::getAbi(&M, abi))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(M, abi);

	std::set<llvm::Instruction*> uses;

	for (Function &F : M)
	for (auto it = inst_begin(&F), eIt = inst_end(&F); it != eIt; ++it)
	{
		Instruction& I = *it;

		if (CallInst* call = dyn_cast<CallInst>(&I))
		{
			if (call->getCalledFunction() == nullptr)
			{
				continue;
			}

			for (auto& a : call->arg_operands())
			{
				auto* aa = dyn_cast_or_null<Instruction>(llvm_utils::skipCasts(a));
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
						&& !d->getSource()->getType()->isFloatingPointTy()
						&& canBeLocalized(d, uses))
				{
					IrModifier::localize(d->def, uses, false);
				}
				// Not necessary to pass all regression tests,
				// but it gives a slight speeds-up.
				else if (abi->isRegister(d->getSource())
						&& canBeLocalized(d, uses))
				{
					IrModifier::localize(d->def, uses, false);
				}
			}
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
