/**
 * @file src/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.cpp
 * @brief Remove all special instructions used to map LLVM instructions to
 *        ASM instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
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
	_config = ConfigProvider::getConfig(&M);
	return run(M);
}

bool AsmInstructionRemover::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_config = c;
	return run(M);
}

/**
 * @return @c True if at least one instruction was removed.
 *         @c False otherwise.
 */
bool AsmInstructionRemover::run(Module& M)
{
	if (_config == nullptr)
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	bool changed = false;

	changed |= renameTempVariables(M);

	for (auto& F : M.getFunctionList())
	for (auto& B : F)
	{
		auto it = B.begin();
		while (it != B.end())
		{
			// We need to move to the next instruction before potentially
			// removing the current instruction. Otherwise, the iterator
			// would become invalid.
			//
			auto* inst = &(*it);
			++it;

			if (_config->isLlvmToAsmInstruction(inst))
			{
				AsmInstruction ai(inst);
				if (cs_insn* insn = ai.getCapstoneInsn())
				{
					cs_free(insn, 1);
				}

				inst->eraseFromParent();
				changed = true;
			}
		}
	}

	if (auto* global = _config->getLlvmToAsmGlobalVariable())
	{
		assert(global->getNumUses() == 0);
		if (global->getNumUses() == 0)
		{
			LOG << "erase: " << llvmObjToString(global) << std::endl;
			global->eraseFromParent();
			changed = true;
		}
	}

	auto* nmd = M.getNamedMetadata("llvmToAsmGlobalVariableName");
	if (nmd)
	{
		nmd->dropAllReferences();
		nmd->eraseFromParent();
	}

	return changed;
}

bool AsmInstructionRemover::renameTempVariables(llvm::Module& M)
{
	bool changed = false;

	for (auto& F : M.getFunctionList())
	for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
	{
		auto addr = ai.getAddress();
		if (addr.isUndefined())
		{
			continue;
		}

		auto addrStr = addr.toHexString();
		unsigned cntr = 0;

		for (auto& i : ai)
		{
			if (!i.getType()->isVoidTy())
			{
				std::string n = "v" + std::to_string(cntr++) + "_" + addrStr;
				i.setName(n);
				changed = true;
			}
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
