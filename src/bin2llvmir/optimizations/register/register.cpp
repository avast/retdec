/**
* @file src/bin2llvmir/optimizations/register/register.cpp
* @brief Solve register pseudo functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/CFG.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Operator.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/register/register.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;
using namespace retdec::bin2llvmir::llvm_utils;

namespace {

std::map<std::pair<std::string, unsigned>, std::string> RegClassNum2Name =
{
	{{"fpr", 0}, "st0"},
	{{"fpr", 1}, "st1"},
	{{"fpr", 2}, "st2"},
	{{"fpr", 3}, "st3"},
	{{"fpr", 4}, "st4"},
	{{"fpr", 5}, "st5"},
	{{"fpr", 6}, "st6"},
	{{"fpr", 7}, "st7"},

	{{"fpu_tag", 0}, "fpu_tag_0"},
	{{"fpu_tag", 1}, "fpu_tag_1"},
	{{"fpu_tag", 2}, "fpu_tag_2"},
	{{"fpu_tag", 3}, "fpu_tag_3"},
	{{"fpu_tag", 4}, "fpu_tag_4"},
	{{"fpu_tag", 5}, "fpu_tag_5"},
	{{"fpu_tag", 6}, "fpu_tag_6"},
	{{"fpu_tag", 7}, "fpu_tag_7"}
};

} // anonymous namespace

namespace retdec {
namespace bin2llvmir {

char RegisterAnalysis::ID = 0;

static RegisterPass<RegisterAnalysis> X(
		"register",
		"Assembly register optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

RegisterAnalysis::RegisterAnalysis() :
		ModulePass(ID)
{

}

bool RegisterAnalysis::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	return run();
}

bool RegisterAnalysis::runOnModuleCustom(
		llvm::Module& m,
		Config* c)
{
	_module = &m;
	_config = c;
	return run();
}

bool RegisterAnalysis::run()
{
	if (_config == nullptr)
	{
		return false;
	}

//dumpModuleToFile(_module);

	bool changed = false;

	top = _module->getNamedGlobal("fpu_stat_TOP");
	if (top == nullptr)
	{
		return changed;
	}
	changed |= x86FpuAnalysis();

//dumpModuleToFile(_module);

	return changed;
}

bool getTopVal(
		llvm::GlobalVariable* top,
		int& topVal,
		llvm::Value* val,
		AsmInstruction& ai)
{
	val = skipCasts(val);

	if (isa<LoadInst>(val)
			&& cast<LoadInst>(val)->getPointerOperand() == top)
	{
		LOG << "\t\t" << ai.getAddress() << " @ " << std::dec << topVal << std::endl;
	}
	else if (isa<AddOperator>(val)
			&& isa<LoadInst>(skipCasts(cast<AddOperator>(val)->getOperand(0)))
			&& cast<LoadInst>(skipCasts(cast<AddOperator>(val)->getOperand(0)))->getPointerOperand() == top
			&& isa<ConstantInt>(cast<AddOperator>(val)->getOperand(1)))
	{
		auto* ci = cast<ConstantInt>(cast<AddOperator>(val)->getOperand(1));
		int tmp = topVal + ci->getSExtValue();
		LOG << "\t\t" << ai.getAddress() << std::dec << " @ " << topVal
				<< " + " << ci->getSExtValue() << " = " << tmp << std::endl;
		topVal = tmp;
	}
	else if (isa<SubOperator>(val)
			&& isa<LoadInst>(skipCasts(cast<SubOperator>(val)->getOperand(0)))
			&& cast<LoadInst>(skipCasts(cast<SubOperator>(val)->getOperand(0)))->getPointerOperand() == top
			&& isa<ConstantInt>(cast<SubOperator>(val)->getOperand(1)))
	{
		auto* ci = cast<ConstantInt>(cast<SubOperator>(val)->getOperand(1));
		int tmp = topVal - ci->getSExtValue();
		LOG << "\t\t" << ai.getAddress() << std::dec << " @ " << topVal
				<< " + " << ci->getSExtValue() << " = " << tmp << std::endl;
		topVal = tmp;
	}
	else if (isa<BinaryOperator>(val)
			&& cast<BinaryOperator>(val)->getOpcode() == Instruction::And
			&& isa<ConstantInt>(cast<BinaryOperator>(val)->getOperand(1)))
	{
		return getTopVal(top, topVal, cast<BinaryOperator>(val)->getOperand(0), ai);
	}
	else if (auto* ci = dyn_cast<ConstantInt>(val))
	{
		topVal = ci->getZExtValue();
	}
	// add i3 top, -4
	// may be optimized into:
	// xor i3 top, -4
	// TODO: does this happen only for -4, or for other constants as well?
	else if (isa<BinaryOperator>(val)
			&& cast<BinaryOperator>(val)->getOpcode() == Instruction::Xor
			&& isa<LoadInst>(skipCasts(cast<BinaryOperator>(val)->getOperand(0)))
			&& cast<LoadInst>(skipCasts(cast<BinaryOperator>(val)->getOperand(0)))->getPointerOperand() == top
			&& isa<ConstantInt>(cast<BinaryOperator>(val)->getOperand(1))
			&& cast<ConstantInt>(cast<BinaryOperator>(val)->getOperand(1))->getSExtValue() == -4)
	{
		auto* ci = cast<ConstantInt>(cast<BinaryOperator>(val)->getOperand(1));
		int tmp = topVal + ci->getSExtValue();
		LOG << "\t\t" << ai.getAddress() << std::dec << " @ " << topVal
				<< " + " << ci->getSExtValue() << " = " << tmp << std::endl;
		topVal = tmp;
	}
	else
	{
		LOG << "\t\t" << ai.getAddress() << std::endl;
		assert(false && "some other pattern");
		return false;
	}

	return true;
}

bool RegisterAnalysis::x86FpuAnalysis()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		LOG << f.getName().str() << std::endl;

		retdec::utils::NonIterableSet<BasicBlock*> seenBbs;
		for (auto& bb : f)
		{
			int topVal = 0;
			changed |= x86FpuAnalysisBb(seenBbs, &bb, topVal);
		}
	}
	return changed;
}

bool RegisterAnalysis::x86FpuAnalysisBb(
		retdec::utils::NonIterableSet<llvm::BasicBlock*>& seenBbs,
		llvm::BasicBlock* bb,
		int topVal)
{
	LOG << "\t" << bb->getName().str() << std::endl;
	bool changed = false;

	if (seenBbs.has(bb))
	{
		LOG << "\t\talready seen" << std::endl;
		return false;
	}
	seenBbs.insert(bb);

	auto it = bb->begin();
	while (it != bb->end())
	{
		auto* i = &(*it);
		++it;

		if (auto* c = isRegisterStoreFunctionCall(i))
		{
			AsmInstruction ai(c);
			std::string regClass = getRegisterClass(
					c->getCalledFunction());

			int tmp = topVal;
			auto* val = skipCasts(c->getArgOperand(0));
			if (!getTopVal(top, tmp, val, ai))
			{
				continue;
			}

			if (tmp >= 0)
			{
				LOG << "\t\toverflow -- fix -- " << tmp << " -> -1" << std::endl;
				tmp = -1;
				topVal = -1;
			}

			int regNum = (std::abs(tmp + 1)) % 8;
			LOG << "\t\tstore -- " << regClass << " -- " << regNum << std::endl;
			LOG << std::endl;

			auto* reg = getLlvmRegister(regClass, regNum);
			new StoreInst(c->getArgOperand(1), reg, c);
			c->eraseFromParent();
			changed = true;
		}
		else if (auto* c = isRegisterLoadFunctionCall(i))
		{
			AsmInstruction ai(c);
			std::string regClass = getRegisterClass(
					c->getCalledFunction());

			int tmp = topVal;
			auto* val = skipCasts(c->getArgOperand(0));
			if (!getTopVal(top, tmp, val, ai))
			{
				continue;
			}

			if (tmp >= 0)
			{
				LOG << "\t\toverflow -- fix -- " << tmp << " -> -1" << std::endl;
				tmp = -1;
				topVal = -1;
			}

			int regNum = (std::abs(tmp + 1)) % 8;
			LOG << "\t\tload -- " << regClass << " -- " << regNum << std::endl;
			LOG << std::endl;

			auto* reg = getLlvmRegister(regClass, regNum);
			auto* l = new LoadInst(reg, "", c);
			auto* conv = IrModifier::convertValueToType(l, c->getType(), c);

			c->replaceAllUsesWith(conv);
			c->eraseFromParent();
			changed = true;
		}
		else if (auto* s = dyn_cast<StoreInst>(i))
		{
			auto* ptr = s->getPointerOperand();
			auto* val = s->getValueOperand();
			if (ptr == top)
			{
				AsmInstruction ai(s);

				int tmp = topVal;
				if (!getTopVal(top, tmp, val, ai))
				{
					continue;
				}
				if (tmp > 0)
				{
					LOG << "\t\toverflow -- fix -- " << tmp << " -> 0" << std::endl;
					tmp = 0;
				}
				topVal = tmp;

				LOG << "\t\tstore -- topVal -- " << topVal << std::endl;
				LOG << std::endl;
			}
		}
	}

	for (auto succIt = succ_begin(bb), e = succ_end(bb); succIt != e; ++succIt)
	{
		auto* succ = *succIt;
		changed |= x86FpuAnalysisBb(seenBbs, succ, topVal);
	}

	return changed;
}

bool RegisterAnalysis::isRegisterStoreFunction(llvm::Function* f)
{
	return f ? retdec::utils::startsWith(f->getName(), _regStoreFncName): false;
}

bool RegisterAnalysis::isRegisterLoadFunction(llvm::Function* f)
{
	return f ? retdec::utils::startsWith(f->getName(), _regLoadFncName): false;
}

llvm::CallInst* RegisterAnalysis::isRegisterStoreFunctionCall(llvm::Value* val)
{
	auto* c = dyn_cast<CallInst>(val);
	return c && isRegisterStoreFunction(c->getCalledFunction()) ? c : nullptr;
}

llvm::CallInst* RegisterAnalysis::isRegisterLoadFunctionCall(llvm::Value* val)
{
	auto* c = dyn_cast<CallInst>(val);
	return c && isRegisterLoadFunction(c->getCalledFunction()) ? c : nullptr;
}

std::string RegisterAnalysis::getRegisterClass(llvm::Function* f)
{
	std::string n = f->getName();
	std::size_t p = n.find_last_of('.');
	return n.substr(p+1);
}

llvm::GlobalVariable* RegisterAnalysis::getLlvmRegister(
		const std::string& regClass,
		unsigned regNum)
{
	auto fIt = RegClassNum2Name.find({regClass, regNum});
	assert(fIt != RegClassNum2Name.end());
	if (fIt == RegClassNum2Name.end())
	{
		return nullptr;
	}

	auto* ret = _config->getLlvmRegister(fIt->second);
	assert(ret);
	return ret;
}

} // namespace bin2llvmir
} // namespace retdec
