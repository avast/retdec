/**
 * @file src/bin2llvmir/optimizations/inst_opt/inst_opt_pass.cpp
 * @brief LLVM instruction optimization pass.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt_pass.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char InstructionOptimizer::ID = 0;

static RegisterPass<InstructionOptimizer> X(
		"inst-opt",
		"LLVM instruction optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

InstructionOptimizer::InstructionOptimizer() :
		ModulePass(ID)
{

}

bool InstructionOptimizer::runOnModule(Module& m)
{
	_module = &m;
	return run();
}

bool InstructionOptimizer::runOnModuleCustom(llvm::Module& m)
{
	_module = &m;
	return run();
}

bool InstructionOptimizer::run()
{
	bool changed = false;

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction* insn = &*it;
		++it;

		changed |= inst_opt::optimize(insn);
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
