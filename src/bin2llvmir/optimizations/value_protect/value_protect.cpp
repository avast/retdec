/**
* @file src/bin2llvmir/optimizations/value_protect/value_protect.cpp
* @brief Protect values from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/bin2llvmir/optimizations/value_protect/value_protect.h"
#include "retdec/bin2llvmir/providers/names.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ValueProtect::ID = 0;

std::map<llvm::Type*, llvm::Function*> ValueProtect::_type2fnc;

static RegisterPass<ValueProtect> X(
		"value-protect",
		"Value protection optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ValueProtect::ValueProtect() :
		ModulePass(ID)
{

}

bool ValueProtect::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool ValueProtect::runOnModuleCustom(llvm::Module& M, Config* c, Abi* abi)
{
	_module = &M;
	_config = c;
	_abi = abi;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool ValueProtect::run()
{
	if (_config == nullptr || _abi == nullptr)
	{
		return false;
	}

	_type2fnc.empty() ? protect() : unprotect();

	return true;
}

void ValueProtect::protect()
{
	_config->getConfig().parameters.frontendFunctions.insert(
			names::generatedUndefFunctionPrefix);

	protectStack();
	protectRegisters();
}

void ValueProtect::protectStack()
{
	for (Function& f : _module->getFunctionList())
	{
		if (f.empty())
		{
			continue;
		}
		auto& bb = f.front();
		for (auto& i : bb)
		{
			// Right now, ww protect all allocas, not only stacks.
			if (auto* a = dyn_cast<AllocaInst>(&i))
			{
				protectValue(a, a->getAllocatedType(), a->getNextNode());
			}
		}
	}
}

void ValueProtect::protectRegisters()
{
	const auto& regs = _abi->getRegisters();

	for (Function& F : _module->getFunctionList())
	{
		if (F.empty() || F.front().empty())
		{
			continue;
		}

		// Protect registers only in functions that are NOT called anywhere.
		//
		bool skip = false;
		for (auto uIt = F.user_begin(); uIt != F.user_end(); ++uIt)
		{
			if (isa<CallInst>(*uIt))
			{
				skip = true;
				break;
			}
		}
		if (skip)
		{
			continue;
		}

		Instruction* first = &F.front().front();
		for (auto* r : regs)
		{
			protectValue(r, r->getValueType(), first);
		}
	}
}

void ValueProtect::protectValue(
		llvm::Value* val,
		llvm::Type* t,
		llvm::Instruction* before)
{
	Function* fnc = getOrCreateFunction(t);
	auto* c = CallInst::Create(fnc);
	c->insertBefore(before);
	auto* s = new StoreInst(c, val);
	s->insertAfter(c);
}

llvm::Function* ValueProtect::getOrCreateFunction(llvm::Type* t)
{
	auto fIt = _type2fnc.find(t);
	return fIt != _type2fnc.end() ? fIt->second : createFunction(t);
}

llvm::Function* ValueProtect::createFunction(llvm::Type* t)
{
	FunctionType* ft = FunctionType::get(t, false);
	auto* fnc = Function::Create(
			ft,
			GlobalValue::ExternalLinkage,
			names::generateFunctionNameUndef(_type2fnc.size()),
			_module);
	_type2fnc[t] = fnc;

	return fnc;
}

/**
 * TODO: Only partial removal, see:
 * https://github.com/avast-tl/retdec/issues/301
 */
void ValueProtect::unprotect()
{
	for (auto& p : _type2fnc)
	{
		auto* fnc = p.second;

		for (auto uIt = fnc->user_begin(); uIt != fnc->user_end();)
		{
			auto* u = *uIt;
			++uIt;

			for (auto uuIt = u->user_begin(); uuIt != u->user_end();)
			{
				auto* uu = *uuIt;
				++uuIt;

				if (auto* s = dyn_cast<StoreInst>(uu))
				{
					s->eraseFromParent();
				}
			}

			Instruction* i = cast<Instruction>(u);
			if (i->user_empty())
			{
				i->eraseFromParent();
			}
		}

		if (fnc->user_empty())
		{
			fnc->eraseFromParent();
		}
	}

	_type2fnc.clear();
}

} // namespace bin2llvmir
} // namespace retdec
