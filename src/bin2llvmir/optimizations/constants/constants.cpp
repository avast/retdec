/**
* @file src/bin2llvmir/optimizations/constants/constants.cpp
* @brief Composite type reconstruction analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/string.h"
#include "retdec/utils/time.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/optimizations/constants/constants.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
const bool debug_enabled = false;
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ConstantsAnalysis::ID = 0;

static RegisterPass<ConstantsAnalysis> X(
		"retdec-constants",
		"Constants optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ConstantsAnalysis::ConstantsAnalysis() :
		ModulePass(ID)
{

}

bool ConstantsAnalysis::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	_image = FileImageProvider::getFileImage(_module);
	_dbgf = DebugFormatProvider::getDebugFormat(_module);
	return run();
}

bool ConstantsAnalysis::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		Abi* a,
		FileImage* i,
		DebugFormat* d)
{
	_module = &m;
	_config = c;
	_abi = a;
	_image = i;
	_dbgf = d;
	return run();
}

bool ConstantsAnalysis::run()
{
	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(*_module, _abi);

	for (Function& f : *_module)
	for (inst_iterator I = inst_begin(&f), E = inst_end(&f); I != E;)
	{
		Instruction& i = *I;
		++I;

		if (StoreInst *store = dyn_cast<StoreInst>(&i))
		{
			if (AsmInstruction::isLlvmToAsmInstruction(store))
			{
				continue;
			}

			checkForGlobalInInstruction(RDA, store, store->getValueOperand(), true);

			if (isa<GlobalVariable>(store->getPointerOperand()))
			{
				continue;
			}

			checkForGlobalInInstruction(RDA, store, store->getPointerOperand());
		}
		else if (auto* load = dyn_cast<LoadInst>(&i))
		{
			if (isa<GlobalVariable>(load->getPointerOperand()))
			{
				continue;
			}

			checkForGlobalInInstruction(RDA, load, load->getPointerOperand());
		}
	}

	IrModifier::eraseUnusedInstructionsRecursive(_toRemove);

	return false;
}

void ConstantsAnalysis::checkForGlobalInInstruction(
		ReachingDefinitionsAnalysis& RDA,
		Instruction* inst,
		Value* val,
		bool storeValue)
{
	LOG << llvmObjToString(inst) << std::endl;

	auto root = SymbolicTree::PrecomputedRda(RDA, val);
	root.simplifyNode();

	LOG << root << std::endl;

	auto* max = root.getMaxIntValue();
	auto* maxC = max ? dyn_cast_or_null<ConstantInt>(max->value) : nullptr;
	Instruction* userI = max ? dyn_cast_or_null<Instruction>(max->user) : nullptr;

	if (max && maxC && maxC->getValue().getActiveBits() <= 64 && maxC->getZExtValue() != 0)
	if (userI || max == &root)
	if (_image->getImage()->hasDataOnAddress(maxC->getZExtValue()))
	{
		IrModifier irm(_module, _config);
		auto* ngv = irm.getGlobalVariable(
				_image,
				_dbgf,
				maxC->getZExtValue(),
				storeValue);

		if (ngv)
		{
			if (max == &root)
			{
				auto* conv = IrModifier::convertConstantToType(ngv, val->getType());
				_toRemove.insert(val);
				inst->replaceUsesOfWith(val, conv);
				return;
			}
			else if (userI)
			{
				auto* conv = IrModifier::convertConstantToType(ngv, maxC->getType());
				userI->replaceUsesOfWith(maxC, conv);
				return;
			}
		}
	}

	auto* gv = dyn_cast<GlobalVariable>(root.value);
	if (isa<LoadInst>(inst) && gv && root.ops.size() <= 1)
	{
		auto* conv = IrModifier::convertConstantToType(gv, val->getType());
		_toRemove.insert(val);
		inst->replaceUsesOfWith(val, conv);
		return;
	}
}

} // namespace bin2llvmir
} // namespace retdec
