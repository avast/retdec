/**
* @file src/bin2llvmir/optimizations/main_detection/main_detection.cpp
* @brief Detect main function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>

#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/optimizations/main_detection/main_detection.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char MainDetection::ID = 0;

static RegisterPass<MainDetection> X(
		"main-detection",
		"Main function identification optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

MainDetection::MainDetection() :
		ModulePass(ID)
{

}

bool MainDetection::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	_names = NamesProvider::getNames(_module);
	return run();
}

bool MainDetection::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		FileImage* img,
		NameContainer* names)
{
	_module = &m;
	_config = c;
	_image = img;
	_names = names;
	return run();
}

bool MainDetection::run()
{
	if (_config == nullptr || _image == nullptr || _names == nullptr)
	{
		return false;
	}
	if (skipAnalysis())
	{
		removeStaticallyLinked();
		return false;
	}

	bool changed = false;
	Address mainAddr;

	if (auto* mf = _module->getFunction("main"))
	{
		if (auto* cf = _config->getConfigFunction(mf))
		{
			mainAddr = cf->getStart();
		}
	}
	if (mainAddr.isUndefined())
	{
		mainAddr = getFromContext();
	}
	if (mainAddr.isUndefined())
	{
		mainAddr = getFromFunctionNames();
	}

	if (!(_config->getConfig().isIda()
			&& _config->getConfig().parameters.isSomethingSelected()))
	{
		changed = applyResult(mainAddr);
	}

	removeStaticallyLinked();

	return changed;
}

bool MainDetection::skipAnalysis()
{
	return _config->getConfig().getMainAddress().isDefined()
			|| _config->getConfig().fileType.isShared();
}

/**
 * Delete statically linked functions bodies only after main detection run.
 * TODO: This is not ideal here, very random, move main detection to decoding?
 * and delete linked bodies right after they have been found?
 * TODO: do this when shared?
 */
void MainDetection::removeStaticallyLinked()
{
	for (Function& f : _module->functions())
	{
		auto* cf = _config->getConfigFunction(&f);
		if (cf && cf->isStaticallyLinked())
		{
			f.deleteBody();
		}
	}
}

retdec::utils::Address MainDetection::getFromFunctionNames()
{
	// Order is important: first -> highest priority, last -> lowest  priority.
	std::vector<std::string> names = {"main", "_main", "wmain", "WinMain"};
	std::pair<Address, unsigned> ret = {Address(), names.size()};

	for (auto& p : _config->getConfig().functions)
	{
		retdec::config::Function& f = p.second;
		auto it = std::find(names.begin(), names.end(), f.getName());
		if (it != names.end())
		{
			auto index = std::distance(names.begin(), it);
			if (index <= ret.second)
			{
				ret = {f.getStart(), index};
			}
		}
	}

	return ret.first;
}

retdec::utils::Address MainDetection::getFromContext()
{
	Address mainAddr;

	// Always try to add address at entry point offset if format is Intel HEX.
	// Clang generates it like this, but since address validity is checked
	// it should not screw other compilers.
	//
	if (_config->getConfig().fileFormat.isIntelHex()
			&& _config->getConfig().architecture.isMipsOrPic32() && _image)
	{
		auto* epSeg = _image->getImage()->getSegmentFromAddress(
				_config->getConfig().getEntryPoint());

		if (epSeg)
		{
			retdec::utils::Address addr = epSeg->getAddress() + 0x10;

			auto ai = AsmInstruction(_module, addr);
			auto pai = ai.getPrev();
			if (ai && pai)
			{
				auto* s1 = pai.getInstructionFirst<StoreInst>();
				auto* s2 = ai.getInstructionFirst<StoreInst>();
				if (s1 && s2
						&& s1->getPointerOperand() == s2->getPointerOperand())
				{
					auto* add = dyn_cast<AddOperator>(s2->getValueOperand());
					if (add)
					{
						auto* l = dyn_cast<LoadInst>(add->getOperand(0));
						if (l && l->getPointerOperand() == s1->getPointerOperand())
						{
							auto* c1 = dyn_cast<ConstantInt>(s1->getValueOperand());
							auto* c2 = dyn_cast<ConstantInt>(add->getOperand(1));
							if (c1 && c2)
							{
								mainAddr = c1->getZExtValue() + c2->getZExtValue();
								return mainAddr;
							}
						}
					}
				}
			}
		}
	}

	auto& tools = _config->getConfig().tools;

	for (auto& ci : tools)
	{
		int major = ci.getMajorVersion();
		int minor = ci.getMinorVersion();

		if (_config->getConfig().architecture.isX86())
		{
			if (ci.isTool("mingw") && major == 4 && minor == 7)
			{
				if (auto ai = AsmInstruction(_module, 0x4013f5))
				{
					auto* c = ai.getInstructionFirst<CallInst>();
					if (c && c->getCalledFunction())
					{
						mainAddr = _config->getFunctionAddress(
								c->getCalledFunction());
					}
				}
			}
			else if (ci.isTool("mingw") && major == 4 && minor == 6)
			{
				if (auto ai = AsmInstruction(_module, 0x4014b4))
				{
					auto* c = ai.getInstructionFirst<CallInst>();
					if (c && c->getCalledFunction())
					{
						mainAddr = _config->getFunctionAddress(
								c->getCalledFunction());
					}
				}
			}
			else if (ci.isMsvc("8.0"))
			{
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromEntryPointOffset(-0x14e);
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromCrtSetCheckCount();
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromInterlockedExchange();
				}
			}
			else if (ci.isMsvc("9.0"))
			{
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromCrtSetCheckCount();
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromInterlockedExchange();
				}
			}
			else if (ci.isMsvc("10.0"))
			{
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromEntryPointOffset(-0x5b);
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromEntryPointOffset(-0x126);
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromCrtSetCheckCount();
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromInterlockedExchange();
				}
			}
			else if (ci.isMsvc("11.0"))
			{
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromEntryPointOffset(-0x82);
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromEntryPointOffset(-0xC8);
				}
			}
			else if (ci.isMsvc())
			{
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromCrtSetCheckCount();
				}
				if (mainAddr.isUndefined())
				{
					mainAddr = getFromInterlockedExchange();
				}
			}
		}
		else if (_config->getConfig().architecture.isMipsOrPic32())
		{
			if (tools.isPspGcc() && major == 4 && minor == 3)
			{
				if (auto ai = AsmInstruction(_module, 0x8900218))
				{
					auto* c = ai.getInstructionFirst<CallInst>();
					if (c && c->getCalledFunction())
					{
						mainAddr = _config->getFunctionAddress(
								c->getCalledFunction());
					}
				}
				// TODO: delay slots one insn farther
				if (auto ai = AsmInstruction(_module, 0x890021c))
				{
					auto* c = ai.getInstructionFirst<CallInst>();
					if (c && c->getCalledFunction())
					{
						mainAddr = _config->getFunctionAddress(
								c->getCalledFunction());
					}
				}
			}
			// llvm-mips-elf 3.X
			//
			else if (_config->getConfig().architecture.isMips()
						&& ci.isGcc()
						&& major == 4
						&& minor == 5)
			{
				if (auto* textSeg = _image->getImage()->getSegment(".text"))
				{
					auto addr = textSeg->getAddress() + 0x10;
					auto ai = AsmInstruction(_module, addr);
					auto prev = ai.getPrev();
					if (ai.isValid() && prev.isValid())
					{
						auto* s = ai.getInstructionFirst<StoreInst>();
						auto* ps = prev.getInstructionFirst<StoreInst>();
						if (s
								&& ps
								&& isa<AddOperator>(s->getValueOperand())
								&& isa<LoadInst>(cast<AddOperator>(s->getValueOperand())->getOperand(0))
								&& isa<ConstantInt>(cast<AddOperator>(s->getValueOperand())->getOperand(1))
								&& isa<ConstantInt>(ps->getValueOperand())
								&& ps->getPointerOperand() == cast<LoadInst>(cast<AddOperator>(s->getValueOperand())->getOperand(0))->getPointerOperand())
						{
							auto* ci1 = cast<ConstantInt>(cast<AddOperator>(s->getValueOperand())->getOperand(1));
							auto* ci2 = cast<ConstantInt>(ps->getValueOperand());
							mainAddr = ci1->getZExtValue() + ci2->getZExtValue();
						}
					}
				}
			}
		}
		else if (_config->getConfig().architecture.isPpc())
		{
			// gcc-powerpc-elf 4.5.X
			// in .rodata is on +4 encoded main() address
			//
			auto* rodataSeg = _image->getImage()->getSegment(".rodata");
			if (ci.isGcc()
					&& major == 4
					&& minor == 5
					&& rodataSeg)
			{
				auto roAddr = rodataSeg->getAddress();
				if (auto* ci = _image->getConstantDefault(roAddr + 4))
				{
					mainAddr = ci->getZExtValue();
				}
			}
		}
		else if (_config->getConfig().architecture.isArmOrThumb())
		{
			if (ci.isGcc() && major == 4 && minor == 1)
			{
				if (auto ai = AsmInstruction(_module, 0x81f8))
				{
					auto* c = ai.getInstructionFirst<CallInst>();
					if (c && c->getCalledFunction())
					{
						mainAddr = _config->getFunctionAddress(
								c->getCalledFunction());
					}
				}
				else if (auto ai = AsmInstruction(_module, 0x81ec))
				{
					auto* c = ai.getInstructionFirst<CallInst>();
					if (c && c->getCalledFunction())
					{
						mainAddr = _config->getFunctionAddress(
								c->getCalledFunction());
					}
				}
			}
		}
	}

	return mainAddr;
}

/**
 * TODO: maybe add wrapper handling as in other functions.
 */
retdec::utils::Address MainDetection::getFromEntryPointOffset(int offset)
{
	Address mainAddr;
	Address ep = _config->getConfig().getEntryPoint();
	Address jmpMainAddr = ep + offset;
	auto ai = AsmInstruction(_module, jmpMainAddr);
	auto* c = ai.getInstructionFirst<CallInst>();
	if (c && c->getCalledFunction())
	{
		mainAddr = _config->getFunctionAddress(c->getCalledFunction());
	}
	return mainAddr;
}

/**
 * Try to find main call at _CrtSetCheckCount + 0x2B.
 * Detect if main is called through wrapper.
 */
retdec::utils::Address MainDetection::getFromCrtSetCheckCount()
{
	Address mainAddr;
	auto* f = _module->getFunction("_CrtSetCheckCount");
	if (f == nullptr)
	{
		return mainAddr;
	}

	for (auto* u : f->users())
	{
		auto* i = dyn_cast<Instruction>(u);
		if (i == nullptr)
		{
			continue;
		}

		auto addr = AsmInstruction::getInstructionAddress(i);
		if (addr.isUndefined())
		{
			continue;
		}

		AsmInstruction aic1(_module, addr + 0x2b);
		auto* c1 = aic1.getInstructionFirst<CallInst>();
		if (c1 && c1->getCalledFunction())
		{
			auto* cf1 = c1->getCalledFunction();

			AsmInstruction aic2(cf1);
			auto* c2 = aic2.getInstructionFirst<CallInst>();
			if (c2 && c2->getCalledFunction())
			{
				auto* cf2 = c2->getCalledFunction();
				mainAddr = _config->getFunctionAddress(cf2);
			}
			else
			{
				mainAddr = _config->getFunctionAddress(cf1);
			}
		}
	}

	return mainAddr;
}

/**
 * Try to find main call at InterlockedExchange + 0x46.
 * Detect if main is called through wrapper.
 */
retdec::utils::Address MainDetection::getFromInterlockedExchange()
{
	Address mainAddr;
	auto* f = _module->getFunction("InterlockedExchange");
	if (f == nullptr)
	{
		return mainAddr;
	}

	for (auto* u : f->users())
	{
		auto* i = dyn_cast<Instruction>(u);
		if (i == nullptr)
		{
			continue;
		}

		auto addr = AsmInstruction::getInstructionAddress(i);
		if (addr.isUndefined())
		{
			continue;
		}

		AsmInstruction aic1(_module, addr + 0x46);
		auto* c1 = aic1.getInstructionFirst<CallInst>();
		if (c1 && c1->getCalledFunction())
		{
			auto* cf1 = c1->getCalledFunction();

			AsmInstruction aic2(cf1);
			auto* c2 = aic2.getInstructionFirst<CallInst>();
			if (c2 && c2->getCalledFunction())
			{
				auto* cf2 = c2->getCalledFunction();
				mainAddr = _config->getFunctionAddress(cf2);
			}
			else
			{
				mainAddr = _config->getFunctionAddress(cf1);
			}
		}
	}

	return mainAddr;
}

bool MainDetection::applyResult(retdec::utils::Address mainAddr)
{
	if (mainAddr.isUndefined())
	{
		return false;
	}

	bool changed = false;

	IrModifier irmodif(_module, _config);
	_config->getConfig().setMainAddress(mainAddr);
	if (auto* f = _config->getLlvmFunction(mainAddr))
	{
		std::string n = f->getName();
		// TODO: better, we want to know it is main, but we do not want to
		// rename it if it is from IDA (and maybe never).
		if (n != "main" && ! _config->getConfig().isIda())
		{
			irmodif.renameFunction(f, "main");
			_names->addNameForAddress(
					mainAddr,
					"main",
					Name::eType::HIGHEST_PRIORITY);
			changed = true;
		}
	}
	// AsmInstruction(_module, mainAddr) -> split?

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
