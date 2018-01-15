/**
 * @file src/bin2llvmir/optimizations/select_functions/select_functions.cpp
 * @brief If ranges or functions are selected in config, remove bodies of all
 *        functions that are not selected.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/optimizations/select_functions/select_functions.h"
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char SelectFunctions::ID = 0;

static RegisterPass<SelectFunctions> X(
		"select-fncs",
		"Selected functions optimization",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

SelectFunctions::SelectFunctions() :
		ModulePass(ID)
{

}

bool SelectFunctions::runOnModule(Module& M)
{
	_config = ConfigProvider::getConfig(&M);
	return run(M);
}

bool SelectFunctions::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_config = c;
	return run(M);
}

bool SelectFunctions::run(Module& M)
{
	if (_config == nullptr)
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	if (!_config->getConfig().parameters.isSomethingSelected())
	{
		return findNotReturningFunctions(M);
	}

	bool changed = false;

//	dumpModuleToFile(&M);

	LOG << "functions:" << std::endl;
	for (auto& f : M.getFunctionList())
	{
		if (f.isDeclaration())
		{
			continue;
		}

		auto* cf = _config->getConfigFunction(&f);
		if (cf == nullptr)
		{
			continue;
		}

		LOG << "\t" << f.getName().str() << ": " << cf->getStart()
				<< " -- " << cf->getEnd() << std::endl;

		bool inRanges = false;
		if (_config->getConfig().isIda()
				&& !_config->getConfig().parameters.selectedRanges.empty())
		{
			auto r = _config->getConfig().parameters.selectedRanges.front();
			if (r.getStart() == cf->getStart())
			{
				inRanges = true;
			}
		}
		else
		{
			retdec::utils::AddressRange fncRange;
			if (cf->getStart().isDefined()
					&& cf->getEnd().isDefined()
					&& cf->getStart() <= cf->getEnd())
			{
				fncRange = retdec::utils::AddressRange(
						cf->getStart(),
						cf->getEnd());
			}
			for (auto& r : _config->getConfig().parameters.selectedRanges)
			{
				if (r.contains(cf->getStart()))
				{
					inRanges = true;
					break;
				}
				if (fncRange.contains(r.getStart()))
				{
					inRanges = true;
					break;
				}
			}
		}
		if (inRanges)
		{
			LOG << "\t\tin ranges -- keep" << std::endl;
			continue;
		}

		bool inFunctions = false;
		for (auto& sf : _config->getConfig().parameters.selectedFunctions)
		{
			if (sf == f.getName())
			{
				inFunctions = true;
				break;
			}
		}
		if (inFunctions)
		{
			_config->getConfig().parameters.selectedNotFoundFunctions.erase(
					f.getName());
			LOG << "\t\tin function -- keep" << std::endl;
			continue;
		}

		LOG << "\t\tdelete body" << std::endl;
		f.deleteBody();
		changed = true;
	}

	changed |= findNotReturningFunctions(M);

	return changed;
}

/**
 * TODO: just experimental. if it works, move it to a separate analysis.
 */
bool SelectFunctions::findNotReturningFunctions(llvm::Module& M)
{
	retdec::utils::NonIterableSet<std::string> exitFncs =
	{
		"exit", "_exit", "ExitThread", "abort", "longjmp", "_Exit",
		"quick_exit", "thrd_exit", "ExitProcess"
	};

	for (auto& f : M.getFunctionList())
	{
		if (f.isDeclaration() || f.empty())
		{
			continue;
		}

		retdec::utils::NonIterableSet<BasicBlock*> seen;
		auto* bb = &(f.front());
		while (bb && seen.hasNot(bb))
		{
			for (Instruction& i : *bb)
			{
				auto* c = dyn_cast<CallInst>(&i);
				if (c && c->getCalledFunction())
				{
					auto* cf = c->getCalledFunction();
					std::string n = cf->getName();
					if (exitFncs.has(n))
					{
						f.setDoesNotReturn();
						bb = nullptr;
						break;
					}
				}
			}

			if (bb == nullptr)
			{
				break;
			}
			else
			{
				seen.insert(bb);
				bb = bb->getSingleSuccessor();
			}
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
