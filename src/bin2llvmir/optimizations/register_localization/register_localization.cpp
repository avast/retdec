/**
* @file src/bin2llvmir/optimizations/register_localization/register_localization.cpp
* @brief Make all registers local.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/optimizations/register_localization/register_localization.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char RegisterLocalization::ID = 0;

static RegisterPass<RegisterLocalization> X(
		"retdec-register-localization",
		"Make all registers local",
		false, // Only looks at CFG
		false // Analysis Pass
);

RegisterLocalization::RegisterLocalization() :
		ModulePass(ID)
{

}

bool RegisterLocalization::runOnModule(Module& M)
{
	_module = &M;
	_abi = AbiProvider::getAbi(_module);
	_config = ConfigProvider::getConfig(_module);
	return run();
}

bool RegisterLocalization::runOnModuleCustom(llvm::Module& M, Abi* a, Config* c)
{
	_module = &M;
	_abi = a;
	_config = c;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool RegisterLocalization::run()
{
	if (_abi == nullptr || _config == nullptr)
	{
		return false;
	}
	const auto& regs = _abi->getRegisters();

	bool changed = false;

	for (GlobalVariable* reg : regs)
	{
		std::map<Function*, AllocaInst*> fnc2alloca;

		for (auto uIt = reg->user_begin(); uIt != reg->user_end(); )
		{
			User* user = *uIt;
			++uIt;

			if (auto* insn = dyn_cast<Instruction>(user))
			{
				changed = localize(reg, fnc2alloca, insn);
			}
			else if (auto* expr = dyn_cast<ConstantExpr>(user))
			{
				for (auto euIt = expr->user_begin(); euIt != expr->user_end(); )
				{
					User* euser = *euIt;
					++euIt;

					if (auto* insn = dyn_cast<Instruction>(euser))
					{
						auto* einsn = expr->getAsInstruction();
						einsn->insertBefore(insn);

						if (localize(reg, fnc2alloca, einsn))
						{
							insn->replaceUsesOfWith(expr, einsn);
							changed = true;
						}
					}
				}
			}
		}
	}

	return changed;
}

llvm::AllocaInst* RegisterLocalization::getLocalized(
		llvm::GlobalVariable* reg,
		llvm::Function* fnc,
		std::map<llvm::Function*, llvm::AllocaInst*>& fnc2alloca)
{
		auto fIt = fnc2alloca.find(fnc);
		if (fIt != fnc2alloca.end())
		{
			return fIt->second;
		}
		else if (!fnc->empty() && !fnc->front().empty())
		{
			auto* a = new AllocaInst(
					reg->getValueType(),
					reg->getAddressSpace(),
					nullptr,
					reg->getName(),
					&fnc->front().front());
			fnc2alloca.emplace(fnc, a);
			return a;
		}
		else
		{
			// Should not really happen.
			return nullptr;
		}
}

bool RegisterLocalization::localize(
		llvm::GlobalVariable* reg,
		std::map<llvm::Function*, llvm::AllocaInst*>& fnc2alloca,
		llvm::Instruction* insn)
{
	AllocaInst* localized = getLocalized(
			reg,
			insn->getFunction(),
			fnc2alloca);

	if (localized == nullptr)
	{
		return false;
	}

	insn->replaceUsesOfWith(reg, localized);
	return true;
}

} // namespace bin2llvmir
} // namespace retdec
