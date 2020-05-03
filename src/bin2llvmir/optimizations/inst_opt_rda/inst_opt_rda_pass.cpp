/**
 * @file src/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda_pass.cpp
 * @brief LLVM instruction optimization pass using RDA.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda_pass.h"
#include "retdec/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char InstructionRdaOptimizer::ID = 0;

static RegisterPass<InstructionRdaOptimizer> X(
		"retdec-inst-opt-rda",
		"LLVM instruction optimization using RDA",
		false, // Only looks at CFG
		false // Analysis Pass
);

InstructionRdaOptimizer::InstructionRdaOptimizer() :
		ModulePass(ID)
{

}

bool InstructionRdaOptimizer::runOnModule(Module& m)
{
	_module = &m;
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool InstructionRdaOptimizer::runOnModuleCustom(llvm::Module& m, Abi* abi)
{
	_module = &m;
	_abi = abi;
	return run();
}

bool InstructionRdaOptimizer::run()
{
	bool changed = false;

	for (Function& f : *_module)
	{
		changed |= runOnFunction(&f);
	}

	return changed;
}

bool InstructionRdaOptimizer::runOnFunction(llvm::Function* f)
{
	bool changed = false;

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnFunction(*f, _abi, true);

	std::unordered_set<llvm::Value*> toRemove;

	for (auto it = inst_begin(f), eIt = inst_end(f); it != eIt;)
	{
		Instruction* insn = &*it;
		++it;

		changed |= inst_opt_rda::optimize(
				insn,
				RDA,
				_abi,
				&toRemove
		);
	}
// exit(1);
	IrModifier::eraseUnusedInstructionsRecursive(toRemove);
	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
