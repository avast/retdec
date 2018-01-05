/**
 * @file src/bin2llvmir/optimizations/volatilize/volatilize.cpp
 * @brief Make all loads and stores volatile to protected them.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/volatilize/volatilize.h"
#include "retdec/bin2llvmir/utils/defs.h"

using namespace retdec::llvm_support;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

char Volatilize::ID = 0;
bool Volatilize::_doVolatilization = true;
UnorderedValSet Volatilize::_alreadyVolatile;

static RegisterPass<Volatilize> X(
		"volatilize",
		"(Un)Volatilize optimization",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

Volatilize::Volatilize() :
		ModulePass(ID)
{

}

/**
 * @return @c True if al least one instruction was (un)volatilized.
 *         @c False otherwise.
 */
bool Volatilize::runOnModule(Module& M)
{
	bool changed = false;
	if (_doVolatilization)
	{
		changed |= volatilize(M);
	}
	else
	{
		changed |= unvolatilize(M);
	}

	return changed;
}

bool Volatilize::volatilize(Module& M)
{
	LOG << "\n*** Volatilize::volatilize()" << std::endl;

	bool changed = false;
	_alreadyVolatile.clear();

	for (auto& F : M.getFunctionList())
	for (auto& B : F)
	for (auto& I : B)
	{
		if (LoadInst* l = dyn_cast<LoadInst>(&I))
		{
			if (l->isVolatile())
			{
				_alreadyVolatile.insert(l);
				LOG << "\t[ALREADY VOL]: " << llvmObjToString(l) << std::endl;
			}
			else
			{
				l->setVolatile(true);
				changed |= true;
				LOG << "\t[VOLATILIZE ]: " << llvmObjToString(l) << std::endl;
			}
		}
		else if (StoreInst* s = dyn_cast<StoreInst>(&I))
		{
			if (s->isVolatile())
			{
				_alreadyVolatile.insert(s);
				LOG << "\t[ALREADY VOL]: " << llvmObjToString(s) << std::endl;
			}
			else
			{
				s->setVolatile(true);
				changed |= true;
				LOG << "\t[VOLATILIZE ]: " << llvmObjToString(s) << std::endl;
			}
		}
	}

	_doVolatilization = false;
	return changed;
}

bool Volatilize::unvolatilize(Module& M)
{
	LOG << "\n*** Volatilize::unvolatilize()" << std::endl;

	bool changed = false;

	for (auto& F : M.getFunctionList())
	for (auto& B : F)
	for (auto& I : B)
	{
		if (LoadInst* l = dyn_cast<LoadInst>(&I))
		{
			if (_alreadyVolatile.count(l))
			{
				LOG << "\t[ALREADY VOL ]: " << llvmObjToString(l) << std::endl;
			}
			else
			{
				l->setVolatile(false);
				changed |= true;
				LOG << "\t[UNVOLATILIZE]: " << llvmObjToString(l) << std::endl;
			}
		}
		else if (StoreInst* s = dyn_cast<StoreInst>(&I))
		{
			if (_alreadyVolatile.count(s))
			{
				LOG << "\t[ALREADY VOL ]: " << llvmObjToString(s) << std::endl;
			}
			else
			{
				s->setVolatile(false);
				changed |= true;
				LOG << "\t[UNVOLATILIZE]: " << llvmObjToString(s) << std::endl;
			}
		}
	}

	_doVolatilization = true;
	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
