/**
* @file src/bin2llvmir/optimizations/cfg_function_detection/cfg_function_detection.cpp
* @brief Detect functions using control flow graph.
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
#include "retdec/utils/time.h"
#include "retdec/bin2llvmir/optimizations/cfg_function_detection/cfg_function_detection.h"
#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/utils/type.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char CfgFunctionDetection::ID = 0;

static RegisterPass<CfgFunctionDetection> X(
		"cfg-fnc-detect",
		"Control flow function detection optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

CfgFunctionDetection::CfgFunctionDetection() :
		ModulePass(ID)
{

}

bool CfgFunctionDetection::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	return run();
}

bool CfgFunctionDetection::runOnModuleCustom(
		llvm::Module& M,
		Config* c,
		FileImage* i)
{
	_module = &M;
	_config = c;
	_image = i;
	return run();
}

bool CfgFunctionDetection::run()
{
	runOne();
	return false;
}

bool CfgFunctionDetection::isArmDataInCode(AsmInstruction& ai)
{
	if (!_config->getConfig().architecture.isArmOrThumb() || _image == nullptr)
	{
		return false;
	}

	auto addr = ai.getAddress();

	uint64_t val = 0;
	if (_image->getImage()->getWord(addr, val))
	{
		if (_image->getImage()->hasDataOnAddress(val))
		{
			return true;
		}
	}
	uint64_t bval = 0;
	uint64_t aval = 0;
	if (_image->getImage()->getWord(addr+4, aval)
			&& _image->getImage()->getWord(addr-4, bval))
	{
		if (_image->getImage()->hasDataOnAddress(aval)
				&& _image->getImage()->hasDataOnAddress(bval))
		{
			return true;
		}
	}

	return false;
}

llvm::Instruction* CfgFunctionDetection::isPotentialSplitInstruction(
		llvm::Instruction* i)
{
	Instruction* ret = dyn_cast<TerminatorInst>(i);

	static retdec::utils::NonIterableSet<std::string> exitFncs =
	{
		"exit", "_exit", "ExitThread", "abort", "longjmp", "_Exit",
		"quick_exit", "thrd_exit", "ExitProcess"
	};

	if (ret == nullptr)
	{
		auto* c = dyn_cast<CallInst>(i);
		if (c && c->getCalledFunction())
		{
			auto* cf = c->getCalledFunction();
			std::string n = cf->getName();

			if (exitFncs.has(n))
			{
				ret = c;
			}
			else if (!cf->empty())
			{
				auto& bb = cf->front();
				for (auto& ii : bb)
				{
					auto* cc = dyn_cast<CallInst>(&ii);
					if (cc && cc->getCalledFunction())
					{
						auto* ccf = cc->getCalledFunction();
						std::string n = ccf->getName();
						if (exitFncs.has(n))
						{
							ret = c;
							break;
						}
					}
				}
			}
		}
	}

	return ret;
}

bool CfgFunctionDetection::runOne()
{

//dumpModuleToFile(_module);
//return false;

	if (_config == nullptr)
	{
		return false;
	}
	if (_config->getConfig().tools.isDelphi())
	{
		return false;
	}

	bool changed = false;
	std::set<AsmInstruction> newFncs;
	IrModifier irmodif(_module, _config);

	for (auto& f : _module->getFunctionList())
	{
		if (f.empty())
		{
			continue;
		}

		std::set<BasicBlock*> bbsBefore;
		std::set<BasicBlock*> bbsAfter;
		for (auto& bb : f)
		{
			bbsAfter.insert(&bb);
		}

		for (auto& bb : f)
		{
			bbsAfter.erase(&bb);
			bbsBefore.insert(&bb);

			if (bbsAfter.empty())
			{
				continue;
			}

			for (auto& i : bb)
			{
				Instruction* ret = isPotentialSplitInstruction(&i);
				if (ret == nullptr)
				{
					continue;
				}

				bool beforeOk = true;
				std::list<BasicBlock*> toRemove;
				for (auto* bb : bbsBefore)
				{
					for (auto* u : bb->users())
					{
						auto* inst = dyn_cast<Instruction>(u);
						assert(inst);

						if (inst->getParent() == ret->getParent())
						{
							for (auto& ii : *ret->getParent())
							{
								if (&ii == inst)
								{
									// first inst -> ok.
									break;
								}
								else if (&ii == ret)
								{
									// first ret -> problem.
									beforeOk = false;
									break;
								}
							}
						}
						if (!beforeOk)
						{
							break;
						}

						if (bbsAfter.count(inst->getParent()))
						{
							beforeOk = false;
							break;
						}
					}
					if (!beforeOk)
					{
						break;
					}
					toRemove.push_back(bb);
				}
				for (auto* bb : toRemove)
				{
					bbsBefore.erase(bb);
				}
				if (!beforeOk)
				{
					continue;
				}

				bool afterOk = true;
				for (auto* bb : bbsAfter)
				{
					for (auto* u : bb->users())
					{
						auto* inst = dyn_cast<Instruction>(u);
						if (inst == nullptr)
						{
							return false;
						}

						bool ok = false;
						if (inst->getParent() == ret->getParent())
						{
							for (auto& ii : *ret->getParent())
							{
								if (&ii == inst)
								{
									// first inst -> problem.
									break;
								}
								else if (&ii == ret)
								{
									// first ret -> ok.
									ok = true;
									break;
								}
							}
						}

						if (bbsAfter.count(inst->getParent()) == 0 && !ok)
						{
							afterOk = false;
							break;
						}
					}
					if (!afterOk)
					{
						break;
					}
				}
				if (!afterOk)
				{
					continue;
				}

				AsmInstruction ai(ret);
				auto aiNext = ai.getNext();
				while (aiNext.isValid()
						&& (aiNext.empty() || isa<ReturnInst>(aiNext.back()) || isArmDataInCode(aiNext)))
				{
					// THUMB: 4 byte data in code offset, 2 byte instructions -- move
					// by 4 bytes, skip one 2 byte instruction.
					if (isArmDataInCode(aiNext) && aiNext.getByteSize() == 2)
					{
						aiNext.eraseInstructions();
						aiNext = aiNext.getNext();
						aiNext.eraseInstructions();
						aiNext = aiNext.getNext();
					}
					else
					{
						aiNext = aiNext.getNext();
					}
				}
				if (aiNext.isInvalid())
				{
					continue;
				}

				newFncs.insert(aiNext);
			}
		}
	}

	LOG << "\nSPLIT ON THESE:" << std::endl;
	LOG << "====================>" << retdec::utils::getElapsedTime() << std::endl;
	for (auto rIt = newFncs.rbegin(), e = newFncs.rend(); rIt != e; ++rIt) // ok
//	for (auto& ai : newFncs) // bad -- slow, we are pushing bb to split before us, it looks like LLVM is not good at bb splice.
//  x86-elf-6c3a2e29e618e3f17c1b32425f6fee52
	{
		auto& ai = *rIt;
		LOG << "\t" << ai.getAddress() << std::endl;

		std::string n;
		if (auto* sym = _image->getPreferredSymbol(ai.getAddress()))
		{
			n = sym->getName();
		}

		irmodif.splitFunctionOn(
				ai.getLlvmToAsmInstruction(),
				ai.getAddress(),
				n);
	}

//exit(1);
//dumpModuleToFile(_module);

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
