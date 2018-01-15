/**
* @file src/bin2llvmir/optimizations/control_flow/powerpc.cpp
* @brief Reconstruct control flow -- PowerPC specific module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/bin2llvmir/optimizations/control_flow/control_flow.h"
#include "retdec/bin2llvmir/utils/type.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool ControlFlow::runPowerpc()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		changed |= runPowerpcFunction(&f);
	}
	return changed;
}

bool ControlFlow::runPowerpcFunction(llvm::Function* f)
{
	bool changed = false;

	auto ai = AsmInstruction(f);
	for (; ai.isValid(); ai = ai.getNext())
	{
		if (runPowerpcReturn(ai))
		{
			changed = true;
			continue;
		}
		else if (runPowerpcCall(ai))
		{
			changed = true;
			continue;
		}
	}

	return changed;
}

bool ControlFlow::runPowerpcReturn(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		if (!_config->isLlvmReturnPseudoFunctionCall(&i))
		{
			continue;
		}
		_toReturn.insert({ai, nullptr});
		return true;
	}

	return false;
}

bool ControlFlow::runPowerpcCall(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		auto* c = _config->isLlvmCallPseudoFunctionCall(&i);
		if (c == nullptr)
		{
			continue;
		}

		auto* ci = dyn_cast<ConstantInt>(c->getArgOperand(0));
		if (ci == nullptr)
		{
			// TODO -- call variable
			// 1.) if RDA available, try to compute it.
			// 2.) if not computed, transform to call of variable.
			continue;
		}

		_toCall.insert({c, ci->getZExtValue()});
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
