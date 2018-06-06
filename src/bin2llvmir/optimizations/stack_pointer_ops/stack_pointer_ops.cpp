/**
* @file src/bin2llvmir/optimizations/stack_pointer_ops/stack_pointer_ops.cpp
* @brief Remove the remaining stack pointer operations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/stack_pointer_ops/stack_pointer_ops.h"
#include "retdec/bin2llvmir/utils/debug.h"

using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

char StackPointerOpsRemove::ID = 0;

static RegisterPass<StackPointerOpsRemove> X(
		"stack-ptr-op-remove",
		"Stack pointer operations optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

StackPointerOpsRemove::StackPointerOpsRemove() :
		ModulePass(ID)
{

}

bool StackPointerOpsRemove::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(&M);
	return run();
}

bool StackPointerOpsRemove::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_module = &M;
	_config = c;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool StackPointerOpsRemove::run()
{
	bool changed = false;
	changed |= removeStackPointerStores();
	changed |= removePreservationStores();

	return changed;
}

bool StackPointerOpsRemove::removeStackPointerStores()
{
	if (_config == nullptr)
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	bool changed = false;
	for (auto& F : _module->getFunctionList())
	for (auto& B : F)
	{
		auto it = B.begin();
		while (it != B.end())
		{
			// We need to move to the next instruction before optimizing
			// (potentially removing) the current instruction. Otherwise,
			// the iterator would become invalid.
			//
			auto* inst = &(*it);
			++it;

			if (StoreInst* s = dyn_cast<StoreInst>(inst))
			{
				auto* reg = s->getPointerOperand();
				if (!_config->isStackPointerRegister(reg))
				{
					continue;
				}

				LOG << "erase: " << llvmObjToString(inst) << std::endl;
				inst->eraseFromParent();
				changed = true;
			}
		}
	}

	return changed;
}

/**
 * Finds those allocas that are only used to store some value from ebp and then
 * this value is stored back to ebp.
 */
bool StackPointerOpsRemove::removePreservationStores()
{
	bool changed = false;

	for (auto& f : _module->getFunctionList())
	{
		for (inst_iterator I = inst_begin(f), E = inst_end(f); I != E; ++I)
		{
			auto* a = dyn_cast<AllocaInst>(&*I);
			if (a == nullptr)
			{
				continue;
			}

			bool remove = true;
			Value* storedVal = nullptr;
			std::set<llvm::Instruction*> toRemove;
			for (auto* u : a->users())
			{
				if (auto* s = dyn_cast<StoreInst>(u))
				{
					auto* l = dyn_cast<LoadInst>(s->getValueOperand());
					if (l && storedVal == nullptr
							&& (l->getPointerOperand()->getName() == "ebp" || l->getPointerOperand()->getName() == "rbp"))
					{
						storedVal = l->getPointerOperand();
						toRemove.insert(s);
					}
					else if (l && l->getPointerOperand() == storedVal)
					{
						toRemove.insert(s);
					}
					else
					{
						remove = false;
						break;
					}
				}
				else if (isa<LoadInst>(u) || isa<CastInst>(u))
				{
					for (auto* uu : u->users())
					{
						auto* s = dyn_cast<StoreInst>(uu);
						if (s && storedVal == nullptr
								&& (s->getPointerOperand()->getName() == "ebp" || s->getPointerOperand()->getName() == "rbp"))
						{
							storedVal = s->getPointerOperand();
							toRemove.insert(s);
						}
						else if (s && s->getPointerOperand() == storedVal)
						{
							toRemove.insert(s);
						}
						else
						{
							remove = false;
							break;
						}
					}

					if (!remove)
					{
						break;
					}
				}
				else
				{
					remove = false;
					break;
				}
			}

			if (remove)
			{
				for (auto* i : toRemove)
				{
					i->eraseFromParent();
					changed = true;
				}
			}
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
