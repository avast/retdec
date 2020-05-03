/**
* @file src/bin2llvmir/optimizations/stack/stack.cpp
* @brief Reconstruct stack.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/stack/stack.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char StackAnalysis::ID = 0;

static RegisterPass<StackAnalysis> X(
		"retdec-stack",
		"Stack optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

StackAnalysis::StackAnalysis() :
		ModulePass(ID)
{

}

bool StackAnalysis::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	_dbgf = DebugFormatProvider::getDebugFormat(_module);
	return run();
}

bool StackAnalysis::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		Abi* abi,
		DebugFormat* dbgf)
{
	_module = &m;
	_config = c;
	_abi = abi;
	_dbgf = dbgf;
	return run();
}

bool StackAnalysis::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(*_module, _abi);

	for (auto& f : *_module)
	{
		std::map<Value*, Value*> val2val;
		for (inst_iterator I = inst_begin(f), E = inst_end(f); I != E;)
		{
			Instruction& i = *I;
			++I;

			if (StoreInst *store = dyn_cast<StoreInst>(&i))
			{
				if (AsmInstruction::isLlvmToAsmInstruction(store))
				{
					continue;
				}

				handleInstruction(
						RDA,
						store,
						store->getValueOperand(),
						store->getValueOperand()->getType(),
						val2val);

				if (isa<GlobalVariable>(store->getPointerOperand()))
				{
					continue;
				}

				handleInstruction(
						RDA,
						store,
						store->getPointerOperand(),
						store->getValueOperand()->getType(),
						val2val);
			}
			else if (LoadInst* load = dyn_cast<LoadInst>(&i))
			{
				if (isa<GlobalVariable>(load->getPointerOperand()))
				{
					continue;
				}

				handleInstruction(
						RDA,
						load,
						load->getPointerOperand(),
						load->getType(),
						val2val);
			}
		}
	}

	IrModifier::eraseUnusedInstructionsRecursive(_toRemove);

	return false;
}

void StackAnalysis::handleInstruction(
		ReachingDefinitionsAnalysis& RDA,
		llvm::Instruction* inst,
		llvm::Value* val,
		llvm::Type* type,
		std::map<llvm::Value*, llvm::Value*>& val2val)
{
	LOG << llvmObjToString(inst) << std::endl;

	auto root = SymbolicTree::PrecomputedRdaWithValueMap(RDA, val, &val2val);
	LOG << root << std::endl;

	if (!root.isVal2ValMapUsed())
	{
		bool stackPtr = false;
		for (SymbolicTree* n : root.getPostOrder())
		{
			if (_abi->isStackPointerRegister(n->value))
			{
				stackPtr = true;
				break;
			}
		}
		if (!stackPtr)
		{
			LOG << "===> no SP" << std::endl;
			return;
		}
	}

	auto* debugSv = getDebugStackVariable(inst->getFunction(), root);
	auto* configSv = getConfigStackVariable(inst->getFunction(), root);

	root.simplifyNode();
	LOG << root << std::endl;

	if (debugSv == nullptr)
	{
		debugSv = getDebugStackVariable(inst->getFunction(), root);
	}

	if (configSv == nullptr)
	{
		configSv = getConfigStackVariable(inst->getFunction(), root);
	}

	auto* ci = dyn_cast_or_null<ConstantInt>(root.value);
	if (ci == nullptr)
	{
		return;
	}

	if (auto* s = dyn_cast<StoreInst>(inst))
	{
		if (s->getValueOperand() == val)
		{
			val2val[inst] = ci;
		}
	}

	LOG << "===> " << llvmObjToString(ci) << std::endl;
	LOG << "===> " << ci->getSExtValue() << std::endl;

	std::string name = "";
	Type* t = type;

	if (debugSv)
	{
		name = debugSv->getName();
		t = llvm_utils::stringToLlvmTypeDefault(_module, debugSv->type.getLlvmIr());
	}
	else if (configSv)
	{
		name = configSv->getName();
		t = llvm_utils::stringToLlvmTypeDefault(_module, configSv->type.getLlvmIr());
	}

	std::string realName;
	if (debugSv)
	{
		realName = debugSv->getName();
	}
	else if (configSv)
	{
		realName = configSv->getName();
	}

	IrModifier irModif(_module, _config);
	auto p = irModif.getStackVariable(
			inst->getFunction(),
			ci->getSExtValue(),
			t,
			name,
			realName,
			debugSv || configSv);

	AllocaInst* a = p.first;

	LOG << "===> " << llvmObjToString(a) << std::endl;
	LOG << "===> " << llvmObjToString(inst) << std::endl;
	LOG << std::endl;

	auto* s = dyn_cast<StoreInst>(inst);
	auto* l = dyn_cast<LoadInst>(inst);
	if (s && s->getPointerOperand() == val)
	{
		auto* conv = IrModifier::convertValueToType(
				s->getValueOperand(),
				a->getType()->getElementType(),
				inst);
		new StoreInst(conv, a, inst);
		_toRemove.insert(s);
	}
	else if (l && l->getPointerOperand() == val)
	{
		auto* nl = new LoadInst(a, "", l);
		auto* conv = IrModifier::convertValueToType(nl, l->getType(), l);
		l->replaceAllUsesWith(conv);
		_toRemove.insert(l);
	}
	else
	{
		auto* conv = IrModifier::convertValueToType(a, val->getType(), inst);
		_toRemove.insert(val);
		inst->replaceUsesOfWith(val, conv);
	}
}

std::optional<int> StackAnalysis::getBaseOffset(SymbolicTree& root)
{
	std::optional<int> baseOffset;
	if (auto* ci = dyn_cast_or_null<ConstantInt>(root.value))
	{
		baseOffset = ci->getSExtValue();
	}
	else
	{
		for (SymbolicTree* n : root.getLevelOrder())
		{
			if (isa<AddOperator>(n->value)
					&& n->ops.size() == 2
					&& isa<LoadInst>(n->ops[0].value)
					&& isa<ConstantInt>(n->ops[1].value))
			{
				auto* l = cast<LoadInst>(n->ops[0].value);
				auto* ci = cast<ConstantInt>(n->ops[1].value);
				if (_abi->isRegister(l->getPointerOperand()))
				{
					baseOffset = ci->getSExtValue();
				}
				break;
			}
		}
	}

	return baseOffset;
}

/**
 * Find a value that is being added to the stack pointer register in \p root.
 * Find a debug variable with offset equal to this value.
 */
const retdec::common::Object* StackAnalysis::getDebugStackVariable(
		llvm::Function* fnc,
		SymbolicTree& root)
{
	auto baseOffset = getBaseOffset(root);
	if (!baseOffset.has_value())
	{
		return nullptr;
	}

	if (_dbgf == nullptr)
	{
		return nullptr;
	}

	auto* debugFnc = _dbgf->getFunction(_config->getFunctionAddress(fnc));
	if (debugFnc == nullptr)
	{
		return nullptr;
	}

	for (auto& var : debugFnc->locals)
	{
		if (!var.getStorage().isStack())
		{
			continue;
		}
		if (var.getStorage().getStackOffset() == baseOffset)
		{
			return &var;
		}
	}

	return nullptr;
}

const retdec::common::Object* StackAnalysis::getConfigStackVariable(
		llvm::Function* fnc,
		SymbolicTree& root)
{
	auto baseOffset = getBaseOffset(root);
	if (!baseOffset.has_value())
	{
		return nullptr;
	}

	auto cfn = _config->getConfigFunction(fnc);
	if (cfn && _config->getLlvmStackVariable(fnc, baseOffset.value()) == nullptr)
	{
		for (auto& var: cfn->locals)
		{
			if (var.getStorage().getStackOffset() == baseOffset)
			{
				return &var;
			}
		}
	}

	return nullptr;
}

} // namespace bin2llvmir
} // namespace retdec
