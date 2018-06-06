/**
 * @file src/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.cpp
 * @brief Remove all special instructions used to map LLVM instructions to
 *        ASM instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/names.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char AsmInstructionRemover::ID = 0;

static RegisterPass<AsmInstructionRemover> X(
		"remove-asm-instrs",
		"Assembly mapping instruction removal",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

AsmInstructionRemover::AsmInstructionRemover() :
		ModulePass(ID)
{

}

bool AsmInstructionRemover::runOnModule(Module& M)
{
	return run(M);
}

bool AsmInstructionRemover::runOnModuleCustom(llvm::Module& M)
{
	return run(M);
}

/**
 * @return @c True if at least one instruction was removed.
 *         @c False otherwise.
 */
bool AsmInstructionRemover::run(Module& M)
{
	bool changed = false;

	for (auto& F : M.getFunctionList())
	for (auto ai = AsmInstruction(&F); ai.isValid();)
	{
		// Set names to instructions.
		//
		unsigned c = 0;
		for (auto& i : ai)
		{
			if (!i.getType()->isVoidTy())
			{
				i.setName(names::generateTempVariableName(ai.getAddress(), c));
				++c;
			}
		}

		// Remove special instructions.
		//
		auto* mapInsn = ai.getLlvmToAsmInstruction();
		ai = ai.getNext();
		mapInsn->eraseFromParent();
		changed = true;
	}

	// Free Capstone instructions.
	//
	auto& insnMap = AsmInstruction::getLlvmToCapstoneInsnMap(&M);
	for (auto& p : insnMap)
	{
		cs_free(p.second, 1);
	}
	insnMap.clear();

	// Remove special global variable.
	//
	if (auto* global = AsmInstruction::getLlvmToAsmGlobalVariable(&M))
	{
		assert(global->getNumUses() == 0);
		if (global->getNumUses() == 0)
		{
			global->eraseFromParent();
			changed = true;
			AsmInstruction::setLlvmToAsmGlobalVariable(&M, nullptr);
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
