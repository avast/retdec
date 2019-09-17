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
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char RegisterLocalization::ID = 0;

std::map<llvm::Type*, llvm::Function*> RegisterLocalization::_type2fnc;

static RegisterPass<RegisterLocalization> X(
		"register-localization",
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
	return run();
}

bool RegisterLocalization::runOnModuleCustom(llvm::Module& M, Abi* abi)
{
	_module = &M;
	_abi = abi;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool RegisterLocalization::run()
{
	if (_abi == nullptr)
	{
		return false;
	}

	bool changed = false;

// std::cout << "RegisterLocalization::run()" << std::endl;
// exit(1);

	const auto& regs = _abi->getRegisters();
	for (Function& F : _module->getFunctionList())
	{
		if (F.empty() || F.front().empty())
		{
			continue;
		}

		for (auto* r : regs)
		{
			Value* localized = nullptr;

			for (auto uIt = r->user_begin(); uIt != r->user_end(); )
			{
				User* user = *uIt;
				++uIt;

				Instruction* insn = dyn_cast<Instruction>(user);
				if (insn)
				{
					if (insn->getFunction() != &F)
					{
						continue;
					}

					if (localized == nullptr)
					{
						localized = new AllocaInst(
								r->getValueType(),
								r->getAddressSpace(),
								nullptr,
								r->getName(),
								&F.front().front());
					}

					insn->replaceUsesOfWith(r, localized);
				}

				// ConstantExpr* expr = dyn_cast<ConstantExpr>(user);
				// if (expr)
				// {
				// 	expr->getpara
				// 	expr->replaceUsesOfWith();
				// }
			}
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
