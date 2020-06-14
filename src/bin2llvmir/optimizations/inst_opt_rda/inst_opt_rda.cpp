/**
 * @file src/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda.cpp
 * @brief Optimize a single LLVM instruction using RDA.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {
namespace inst_opt_rda {

/**
 * store i1 %a, i1* <reg/local>
 * ...
 * reg/local never used
 *   =>
 * remove store
 */
bool unusedStores(llvm::Instruction* insn, ReachingDefinitionsAnalysis& RDA)
{
	auto* abi = AbiProvider::getAbi(insn->getModule());
	auto* store = llvm::dyn_cast<llvm::StoreInst>(insn);
	if (store == nullptr
			|| (llvm::isa<llvm::GlobalVariable>(store->getPointerOperand())
			&& !abi->isRegister(store->getPointerOperand())))
	{
		return false;
	}

	auto* def = RDA.getDef(store);
	// We want to find definition in RDA.
	// We don't want to optimize stores to temporaries like:
	// store i32 %a, i32* %temp
	if (def == nullptr)
	{
		return false;
	}

	if (def->uses.empty())
	{
		IrModifier::eraseUnusedInstructionRecursive(store);
		return true;
	}

	return false;
}

/**
 * bb:
 *     store i32 a, i32* reg
 *     ...
 *     ; There is a single definition for this reg use in the same BB
 *     ; before/above this use.
 *     b = load i32, i32* reg
 * ==>
 * bb:
 *     ; Even this is removed, if this definition has no other use than the
 *     ; load we just eliminated.
 *     store i32 a, i32* reg
 *     ...
 *     ; replace uses of b with a
 */
bool usesWithOneDefInSameBb(
		llvm::Instruction* insn,
		ReachingDefinitionsAnalysis& RDA)
{
	auto* load = llvm::dyn_cast<llvm::LoadInst>(insn);
	if (load == nullptr)
	{
		return false;
	}

	auto* use = RDA.getUse(load);
	if (use == nullptr
			|| use->use == nullptr
			|| use->defs.size() != 1
			|| (*use->defs.begin())->def == nullptr
			|| use->use->getParent() != (*use->defs.begin())->def->getParent())
	{
		return false;
	}

	auto* def = *use->defs.begin();
	auto* store = llvm::dyn_cast<StoreInst>(def->def);
	if (store == nullptr)
	{
		return false;
	}

	// llvm::OrderedBasicBlock obb(use->use->getParent());
	if (!def->dominates(use))
	{
		return false;
	}

	load->replaceAllUsesWith(store->getValueOperand());
	IrModifier::eraseUnusedInstructionRecursive(load);

	if (def->uses.size() == 1)
	{
		IrModifier::eraseUnusedInstructionRecursive(def->def);
	}

	return true;
}

bool defWithUsesInTheSameBb(
		llvm::Instruction* insn,
		ReachingDefinitionsAnalysis& RDA,
		Abi* abi,
		std::unordered_set<llvm::Value*>* toRemove)
{
	auto* store = llvm::dyn_cast<llvm::StoreInst>(insn);
	if (store == nullptr
			|| (llvm::isa<llvm::GlobalVariable>(store->getPointerOperand())
			&& !abi->isRegister(store->getPointerOperand())))
	{
		return false;
	}

	auto* def = RDA.getDef(store);
	if (def == nullptr)
	{
		return false;
	}

	if (llvm::isa<llvm::AllocaInst>(def->src))
	for (auto* u : def->src->users())
	{
		if (!(llvm::isa<llvm::LoadInst>(u) || llvm::isa<llvm::StoreInst>(u)))
		{
			return false;
		}
	}

	bool ret = false;
	bool allUsesRemoved = true;
	for (auto* use : def->uses)
	{
		if (use->use
				&& store->getParent() == use->use->getParent()
				&& llvm::isa<llvm::LoadInst>(use->use)
				&& def->dominates(use))
		{
			use->use->replaceAllUsesWith(store->getValueOperand());
			if (toRemove)
			{
				toRemove->insert(use->use);
			}
			else
			{
				IrModifier::eraseUnusedInstructionRecursive(use->use);
			}
			ret = true;
		}
		else
		{
			allUsesRemoved = false;
		}
	}

	if (allUsesRemoved)
	{
		if (toRemove)
		{
			toRemove->insert(store);
		}
		else
		{
			IrModifier::eraseUnusedInstructionRecursive(store);
		}
	}

	return ret;
}

/**
 * Order here is important.
 * More specific patterns must go first, more general later.
 */
std::vector<bool (*)(
		llvm::Instruction*,
		ReachingDefinitionsAnalysis&,
		Abi*,
		std::unordered_set<llvm::Value*>*
		)> optimizations =
{
		// &unusedStores,
		// &usesWithOneDefInSameBb,
		&defWithUsesInTheSameBb,
};

bool optimize(
		llvm::Instruction* insn,
		ReachingDefinitionsAnalysis& RDA,
		Abi* abi,
		std::unordered_set<llvm::Value*>* toRemove)
{
	for (auto& f : optimizations)
	{
		if (f(insn, RDA, abi, toRemove))
		{
			return true;
		}
	}
	return false;
}

} // namespace inst_opt_rda
} // namespace bin2llvmir
} // namespace retdec