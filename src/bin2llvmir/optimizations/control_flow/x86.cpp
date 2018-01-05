/**
* @file src/bin2llvmir/optimizations/control_flow/x86.cpp
* @brief Reconstruct control flow -- x86 specific module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/control_flow/control_flow.h"
#include "retdec/bin2llvmir/utils/type.h"

#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool ControlFlow::runX86()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		changed |= runX86Function(&f);
	}
	return changed;
}

bool ControlFlow::runX86Function(llvm::Function* f)
{
	bool changed = false;

	auto ai = AsmInstruction(f);
	for (; ai.isValid(); ai = ai.getNext())
	{
		if (runx86Return(ai))
		{
			changed = true;
			continue;
		}
		else if (runx86Call(ai))
		{
			changed = true;
			continue;
		}
	}

	return changed;
}

bool ControlFlow::runx86Return(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		if (!_config->isLlvmReturnPseudoFunctionCall(&i))
		{
			continue;
		}
		// All of these write to gpr4 = esp.
		// Far variants also write to seg1.
		// I do not think we need to keep these definitions -> ASM is erased.
		_toReturn.insert({ai, nullptr});
		return true;
	}

	return false;
}

bool ControlFlow::runx86Call(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		auto* c = _config->isLlvmCallPseudoFunctionCall(&i);
		if (c == nullptr)
		{
			continue;
		}
		auto* op = c->getArgOperand(0);

		retdec::utils::Address addr;
		if (auto* ci = dyn_cast<ConstantInt>(op))
		{
			addr = ci->getZExtValue();
		}
		// we can do it here:
		// bugs.799.x86_elf_8e2d7ac57bded5f52a6b5cd6d769da31
		// LOAD:0804812E                 call    off_8049398
		//
		// we can not do it always:
		// ackermann.x86.gcc-4.7.2.O0.g.elf
		// LOAD:0804812E                 call    off_8049398
		//
		else if (auto* l = dyn_cast<LoadInst>(op))
		{
			auto* pop = skipCasts(l->getPointerOperand());
			if (auto* ci1 = dyn_cast<ConstantInt>(pop))
			{
				retdec::utils::Address a = ci1->getZExtValue();
				auto* f1 = _config->getLlvmFunction(a);
				auto* cf1 = _config->getConfigFunction(a);
				auto* ci2 = _image->getConstantDefault(a);

				if (f1 && cf1 && cf1->isDynamicallyLinked())
				{
					addr = a;
				}
				else if (ci2 && _config->getLlvmFunction(ci2->getZExtValue()))
				{
					addr = ci2->getZExtValue();
				}
				else if (ci2 && AsmInstruction(_module, ci2->getZExtValue()))
				{
					addr = ci2->getZExtValue();
				}
				else if (cf1)
				{
					addr = a;
				}
			}
		}

		if (addr.isUndefined())
		{
			// TODO -- call variable
			// 1.) if RDA available, try to compute it.
			// 2.) if not computed, transform to call of variable.
			continue;
		}

		_toCall.insert({c, addr});
		return true;
	}

	return false;
}

retdec::config::Function* callsDynamic(Config* _config, AsmInstruction ai)
{
	if (ai.getCapstoneInsn()->id != X86_INS_JMP)
	{
		return nullptr;
	}

	auto* c = ai.getInstructionFirst<CallInst>();
	auto* f = c ? c->getCalledFunction() : nullptr;
	auto* cf = f ? _config->getConfigFunction(f) : nullptr;
	if (c == nullptr || f == nullptr || cf == nullptr || !cf->isDynamicallyLinked())
	{
		return nullptr;
	}
	return cf;
}

bool handleDynamicFncCall(Config* _config, IrModifier& _irmodif, AsmInstruction startAi, AsmInstruction lastAi)
{
	auto* cf = callsDynamic(_config, startAi);
	if (cf == nullptr)
	{
		return false;
	}

	auto* fnc = startAi.getFunction();
	auto first = AsmInstruction(fnc);
	std::string n = fnc->getName();
	if (startAi == first)
	{
		LOG << startAi.getAddress() << " -> " << cf->getName() << " HAS FNC" << std::endl;

		if (retdec::utils::startsWith(n, "function_")
				|| retdec::utils::startsWith(n, "sub_"))
		{
			_irmodif.renameFunction(fnc, "_" + cf->getName());
		}

		if (auto afterAi = lastAi.getNext())
		{
			_irmodif.splitFunctionOn(
					afterAi.getLlvmToAsmInstruction(),
					afterAi.getAddress());
		}
	}
	else
	{
		LOG << startAi.getAddress() << " -> " << cf->getName() << " HAS NOT FNC" << std::endl;

		_irmodif.splitFunctionOn(
				startAi.getLlvmToAsmInstruction(),
				startAi.getAddress(),
				"_" + cf->getName());

		if (auto afterAi = lastAi.getNext())
		{
			_irmodif.splitFunctionOn(
					afterAi.getLlvmToAsmInstruction(),
					afterAi.getAddress());
		}
	}

	return true;
}

llvm::Function* getFirstPrevDefinition(llvm::Function* fnc)
{
	if (fnc == nullptr)
	{
		return nullptr;
	}

	auto it = fnc->getIterator();
	if (it != fnc->getParent()->begin())
	{
		--it;
	}
	else
	{
		return nullptr;
	}
	auto* res = &(*it);

	while (res && res->isDeclaration())
	{
		if (it != fnc->getParent()->begin())
		{
			--it;
		}
		else
		{
			return nullptr;
		}
		res = &(*it);
	}
	return res;
}

bool ControlFlow::runX86JmpNopNopPattern()
{
	std::set<Function*> found;
	bool changed = false;
	for (auto& fnc : *_module)
	{
		auto first = AsmInstruction(&fnc);
		auto ai = first;

		for (; ai.isValid(); ai = ai.getNext())
		{
			if (!callsDynamic(_config, ai))
			{
				continue;
			}
			auto n1 = ai.getNext();
			if (n1.isInvalid())
			{
				if (handleDynamicFncCall(_config, _irmodif, ai, ai))
				{
					found.insert(&fnc);
				}
				continue;
			}
			if (n1.getCapstoneInsn()->id != X86_INS_NOP
					&& n1.getCapstoneInsn()->id != X86_INS_INT3)
			{
				auto* prev1 = getFirstPrevDefinition(&fnc);
				auto* prev2 = getFirstPrevDefinition(prev1);
				if (ai == first && found.count(prev1) && found.count(prev2))
				{
					if (handleDynamicFncCall(_config, _irmodif, ai, ai))
					{
						found.insert(&fnc);
					}
				}
				continue;
			}
			auto n2 = n1.getNext();
			if (n2.isInvalid())
			{
				if (handleDynamicFncCall(_config, _irmodif, ai, n1))
				{
					found.insert(&fnc);
				}
				continue;
			}
			if (n2.getCapstoneInsn()->id != X86_INS_NOP
					&& n2.getCapstoneInsn()->id != X86_INS_INT3)
			{
				continue;
			}

			if (handleDynamicFncCall(_config, _irmodif, ai, n2))
			{
				found.insert(&fnc);
			}
		}
	}
	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
