/**
* @file src/bin2llvmir/optimizations/stack_protect/stack_protect.cpp
* @brief Protect stack variables from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>
#include <stack>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#define debug_enabled false
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/stack_protect/stack_protect.h"
#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char StackProtect::ID = 0;

std::map<llvm::Type*, llvm::Function*> StackProtect::_type2fnc;

static RegisterPass<StackProtect> X(
		"stack-protect",
		"Stack protection optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

StackProtect::StackProtect() :
		ModulePass(ID)
{

}

bool StackProtect::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(&M);
	return run();
}

bool StackProtect::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_module = &M;
	_config = c;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool StackProtect::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	bool changed = false;

	if (!_type2fnc.empty())
	{
		changed |= unprotectStack(nullptr);
	}
	else
	{
		changed |= protectStack();
	}

	return changed;
}

bool StackProtect::protectStack()
{
	_config->getConfig().parameters.frontendFunctions.insert(_fncName);

	for (auto& F : _module->getFunctionList())
	for (auto& B : F)
	for (auto& I : B)
	{
		auto* a = dyn_cast<AllocaInst>(&I);
		if (!_config->isStackVariable(a))
		{
			continue;
		}

		for (auto* u : a->users())
		{
			auto* s = dyn_cast<StoreInst>(u);
			if (s && s->getPointerOperand() == a && s->getParent() == a->getParent())
			{
				continue;
			}
		}

		Function* fnc = nullptr;

		auto* t = a->getAllocatedType();
		auto fIt = _type2fnc.find(t);
		if (fIt != _type2fnc.end())
		{
			fnc = fIt->second;
		}
		else
		{
			FunctionType* ft = FunctionType::get(
					t,
					false);
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					_fncName + std::to_string(_type2fnc.size()),
					_module);

			_type2fnc[t] = fnc;
		}

		auto* c = CallInst::Create(fnc);
		c->insertAfter(a);
		auto* conv = convertValueToTypeAfter(c, t, c);
		assert(isa<Instruction>(conv));
		auto* s = new StoreInst(conv, a);
		s->insertAfter(cast<Instruction>(conv));
	}

	if (_config->getConfig().isIda()
			&& _config->getConfig().parameters.isSomethingSelected())
	{
		for (auto& F : _module->getFunctionList())
		{
			if (F.isDeclaration())
			{
				continue;
			}

			for (auto& gv : _module->globals())
			{
				if (!_config->isRegister(&gv))
				{
					continue;
				}

				Function* fnc = nullptr;

				auto* t = gv.getValueType();
				auto fIt = _type2fnc.find(t);
				if (fIt != _type2fnc.end())
				{
					fnc = fIt->second;
				}
				else
				{
					FunctionType* ft = FunctionType::get(
							t,
							false);
					fnc = Function::Create(
							ft,
							GlobalValue::ExternalLinkage,
							_fncName + std::to_string(_type2fnc.size()),
							_module);

					_type2fnc[t] = fnc;
				}

				auto it = inst_begin(&F);
				assert(it != inst_end(&F));
				auto* firstI = &*it;

				auto* c = CallInst::Create(fnc);
				c->insertBefore(firstI);
				auto* conv = convertValueToTypeAfter(c, t, c);
				assert(isa<Instruction>(conv));
				auto* s = new StoreInst(conv, &gv);
				s->insertAfter(cast<Instruction>(conv));
			}
		}
	}

	return true;
}

bool StackProtect::unprotectStack(llvm::Function* f)
{
	for (auto& p : _type2fnc)
	{
		std::set<Instruction*> toEraseUse;
		std::set<Instruction*> toErase;
//		std::set<std::tuple<User*, Value*, Value*>> toReplace;

		auto* fnc = p.second;
		for (auto* u : fnc->users())
		{
			CallInst* c = dyn_cast<CallInst>(u);
			assert(c);

			if (c->use_empty())
			{
				toErase.insert(c);
			}
			else if (c->hasOneUse() && isa<StoreInst>(*c->users().begin()))
			{
				toErase.insert(c);
				toEraseUse.insert(cast<StoreInst>(*c->users().begin()));
			}
// TODO: When we do this, we remove all protector functions in bin2llvmirl,
// => there is no need to add them to config and handle them in backeend as well.
// The problem is that 3 regression tests fail, it looks like backend is
// behaving differently when values are tagged with undefined functions and when
// undefined alloca is used. Try to solve it with Petr, because otherwise this
// is a better solution.
//
//			else
//			{
//				LoadInst* l = nullptr;
//				for (auto* uu : c->users())
//				{
//					if (auto* s = dyn_cast<StoreInst>(uu))
//					{
//						toErase.insert(c);
//						toEraseUse.insert(s);
//					}
//					else
//					{
//						if (l == nullptr)
//						{
//							auto* a = new AllocaInst(c->getType(), "", c);
//							l = new LoadInst(a, "", false, c);
//						}
//
//						toReplace.insert(std::make_tuple(uu, c, l));
//					}
//				}
//			}
		}

//		for (auto& t : toReplace)
//		{
//			std::get<0>(t)->replaceUsesOfWith(std::get<1>(t), std::get<2>(t));
//		}

		for (auto* e : toEraseUse)
		{
			e->eraseFromParent();
		}
		for (auto* e : toErase)
		{
			e->eraseFromParent();
		}

//		fnc->eraseFromParent();
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
