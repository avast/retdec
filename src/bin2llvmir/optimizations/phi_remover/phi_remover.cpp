/**
 * @file src/bin2llvmir/optimizations/phi_remover/phi_remover.cpp
 * @brief Remove all Phi nodes (instructions).
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>

#include <llvm/Transforms/Utils/Local.h>

#include "retdec/bin2llvmir/optimizations/phi_remover/phi_remover.h"

namespace retdec {
namespace bin2llvmir {

char PhiRemover::ID = 0;

static llvm::RegisterPass<PhiRemover> X(
		"remove-phi",
		"Phi removal",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

PhiRemover::PhiRemover() :
		ModulePass(ID)
{

}

bool PhiRemover::runOnModule(llvm::Module& M)
{
	return run(M);
}

bool PhiRemover::runOnModuleCustom(llvm::Module& M)
{
	return run(M);
}

/**
 * @return @c True if at least one instruction was removed.
 *         @c False otherwise.
 */
bool PhiRemover::run(llvm::Module& M)
{
	bool changed = false;

	for (llvm::Function& f : M)
	{
		if (f.isDeclaration())
		{
			continue;
		}

		auto* entryBb = &f.getEntryBlock();
		llvm::BasicBlock::iterator insertIt = entryBb->begin();
   		while (llvm::isa<llvm::AllocaInst>(insertIt))
		{
			++insertIt;
		}
		llvm::Instruction* insertInsn = &(*insertIt);

		for (auto it = llvm::inst_begin(&f), eIt = llvm::inst_end(&f); it != eIt;)
		{
			llvm::Instruction* insn = &*it;
			++it;

			if (auto* phi = llvm::dyn_cast<llvm::PHINode>(insn))
			{
				llvm::DemotePHIToStack(phi, insertInsn);
				changed = true;
			}
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
