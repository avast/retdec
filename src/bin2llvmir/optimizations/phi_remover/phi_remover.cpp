/**
 * @file src/bin2llvmir/optimizations/phi_remover/phi_remover.cpp
 * @brief Remove all Phi nodes (instructions).
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>

#include <llvm/Transforms/Utils/Local.h>

#include "retdec/bin2llvmir/optimizations/phi_remover/phi_remover.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"

namespace retdec {
namespace bin2llvmir {

char PhiRemover::ID = 0;

static llvm::RegisterPass<PhiRemover> X(
		"retdec-remove-phi",
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
	_module = &M;
	_config = ConfigProvider::getConfig(_module);
	return run();
}

bool PhiRemover::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_module = &M;
	_config = c;
	return run();
}

common::Address getInstAddress(const llvm::Instruction *i)
{
	if (llvm::MDNode* mdn = i->getMetadata("insn.addr"))
	{
		llvm::ConstantInt* CI = llvm::mdconst::dyn_extract<llvm::ConstantInt>(
			mdn->getOperand(0));
		return CI->getZExtValue();
	}

	return common::Address::Undefined;
}

llvm::MDNode* getInstAddressMeta(common::Address a, llvm::Module* m)
{
	return llvm::MDNode::get(
		m->getContext(),
		llvm::ValueAsMetadata::get(llvm::ConstantInt::get(
			llvm::Type::getInt64Ty(m->getContext()),
			a,
			false
		))
	);
}

/**
 * @return @c True if at least one instruction was removed.
 *         @c False otherwise.
 */
bool PhiRemover::run()
{
	bool changed = false;

	for (llvm::Function& f : *_module)
	{
		if (f.isDeclaration())
		{
			continue;
		}

		auto faddr = _config->getFunctionAddress(&f);
		llvm::MDNode* fmeta = nullptr;

		auto* entryBb = &f.getEntryBlock();
		llvm::BasicBlock::iterator insertIt = entryBb->begin();
		while (llvm::isa<llvm::AllocaInst>(insertIt))
		{
			++insertIt;
		}

		for (auto it = llvm::inst_begin(&f), eIt = llvm::inst_end(&f); it != eIt;)
		{
			llvm::Instruction* insn = &*it;
			++it;

			if (auto* phi = llvm::dyn_cast<llvm::PHINode>(insn))
			{
				if (fmeta == nullptr)
				{
					fmeta = getInstAddressMeta(faddr, _module);
				}

				changed |= demotePhiToStack(phi, fmeta);
			}
		}
	}

	return changed;
}

/**
 * Code taken from llvm::DemotePHIToStack().
 * We need to implement it ourselves in order to add instruction
 * address metadata to newly created instructions.
 */
bool PhiRemover::demotePhiToStack(
		llvm::PHINode* phi,
		llvm::MDNode* faddr)
{
	if (phi->use_empty())
	{
		phi->eraseFromParent();
		return true;
	}

	const llvm::DataLayout& DL = phi->getModule()->getDataLayout();

	// Create a stack slot to hold the value.
	llvm::Function *F = phi->getParent()->getParent();
	auto* alloca = new llvm::AllocaInst(
			phi->getType(),
			DL.getAllocaAddrSpace(),
			nullptr,
			phi->getName() + ".reg2mem",
			&F->getEntryBlock().front()
	);
	alloca->setMetadata("insn.addr", faddr);

	// Iterate over each operand inserting a store in each predecessor.
	for (unsigned i = 0, e = phi->getNumIncomingValues(); i < e; ++i)
	{
		if (auto *II = llvm::dyn_cast<llvm::InvokeInst>(phi->getIncomingValue(i)))
		{
			assert(II->getParent() != phi->getIncomingBlock(i) &&
			"Invoke edge not supported yet"); (void)II;
		}
		auto* insertInsn = phi->getIncomingBlock(i)->getTerminator();
		auto a = getInstAddress(insertInsn);
		auto* s = new llvm::StoreInst(
				phi->getIncomingValue(i),
				alloca,
				insertInsn);
		if (a.isDefined())
		{
			s->setMetadata("insn.addr", getInstAddressMeta(a, _module));
		}
	}

	// Insert a load in place of the PHI and replace all uses.
	llvm::BasicBlock::iterator InsertPt = phi->getIterator();

	for (; llvm::isa<llvm::PHINode>(InsertPt) || InsertPt->isEHPad(); ++InsertPt)
	/* empty */;   // Don't insert before PHI nodes or landingpad instrs.

	auto a = getInstAddress(phi);
	auto* l = new llvm::LoadInst(
			alloca,
			phi->getName() + ".reload",
			&*InsertPt);
	if (a.isDefined())
	{
		l->setMetadata("insn.addr", getInstAddressMeta(a, _module));
	}
	phi->replaceAllUsesWith(l);

	// Delete PHI.
	phi->eraseFromParent();
	return alloca;
}

} // namespace bin2llvmir
} // namespace retdec
