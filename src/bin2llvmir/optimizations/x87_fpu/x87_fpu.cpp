/**
* @file src/bin2llvmir/optimizations/x87_fpu/x87_fpu.cpp
* @brief x87 FPU analysis - replace fpu stack operations with FPU registers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/CFG.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/optimizations/x87_fpu/x87_fpu.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;
using namespace retdec::bin2llvmir::llvm_utils;

namespace retdec {
namespace bin2llvmir {

char X87FpuAnalysis::ID = 0;

static RegisterPass<X87FpuAnalysis> X(
		"x87-fpu",
		"x87 fpu register analysis",
		false, // Only looks at CFG
		false // Analysis Pass
);

X87FpuAnalysis::X87FpuAnalysis() :
		ModulePass(ID)
{

}

bool X87FpuAnalysis::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool X87FpuAnalysis::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		Abi* a)
{
	_module = &m;
	_config = c;
	_abi = a;
	return run();
}

bool X87FpuAnalysis::run()
{
	if (_config == nullptr || _abi == nullptr)
	{
		return ANALYZE_FAIL;
	}
	if (!_abi->isX86())
	{
		return ANALYZE_FAIL;
	}

	top = _abi->getRegister(X87_REG_TOP);
	if (top == nullptr)
	{
		return ANALYZE_FAIL;
	}

	for (Function& f : *_module)
	{
		LOG << f.getName().str() << std::endl;
		std::map<Value*, int> topVals;

		if (f.empty())
			continue;

		auto& bb = f.front();

		int topVal = 8;
		// analyze body of function without nested blocks (branches, loops)
		if (!analyzeBasicBlock(topVals, &bb, topVal))
		{
			return ANALYZE_FAIL;
		}
		if (!analyzeFunctionReturn(f, topVal, analyzedFunctions))
		{
			return ANALYZE_FAIL;
		}

		if (!analyzeNestedBasicBlocks(f, topVal, topVals))
		{
			return ANALYZE_FAIL;
		}

		if (isFunctionDefinitionAndCallMatching(f))
		{
			return ANALYZE_FAIL;
		}
	}

	optimizeAnalyzedFpuInstruction();
	return ANALYZE_SUCCESS;
}

bool X87FpuAnalysis::analyzeNestedBasicBlocks(
		llvm::Function& function,
		int topVal,
		std::map<Value*, int> topVals)
{
	while(!nestedBlocksQueue.empty())
	{
		auto pair = nestedBlocksQueue.front();
		auto nestedBb = pair.first;
		topVal = pair.second;
		nestedBlocksQueue.pop();

		for (auto it = function.begin(); it != function.end(); it++)
		{
			if (nestedBb == it.operator->()
				&& !analyzeBasicBlock(topVals, it.operator->(), topVal))
			{
				return ANALYZE_FAIL;
			}
		}
	}

	return ANALYZE_SUCCESS;
}

bool X87FpuAnalysis::isFunctionDefinitionAndCallMatching(llvm::Function& f)
{
	return calledButNotAnalyzedFunctions.find(f.getGUID()) != calledButNotAnalyzedFunctions.end()
	&& calledButNotAnalyzedFunctions[f.getGUID()] != analyzedFunctions[f.getGUID()];
}

int X87FpuAnalysis::expectedTopBasedOnCallingConvention(llvm::Function& function)
{
	using CallingConvention = config::CallingConvention::eCallingConvention;

	auto configFunctionMetadata = _config->getConfig().functions.getFunctionByName(function.getName());
	if (!configFunctionMetadata)
		return UNKNOWN_CALLING_CONVENTION;

	auto convention = configFunctionMetadata->callingConvention.getID();

	if (_config->getConfig().architecture.isX86_16())
	{
		switch (convention)
		{
			case CallingConvention::CC_CDECL:
			case CallingConvention::CC_PASCAL:
			case CallingConvention::CC_FASTCALL:
				return EMPTY_FPU_STACK;
			case CallingConvention::CC_WATCOM:
				return INCONSISTENT_CALLING_CONVENTION;
			case CallingConvention::CC_UNKNOWN:
				return EMPTY_FPU_STACK; // in this case we know that 16bit arch. almost for sure is empty
			default:
				return UNKNOWN_CALLING_CONVENTION; // some other call canvention witch we dont know
		}
	}
	else if (_config->getConfig().architecture.isX86_32())
	{
		switch (convention)
		{
			case CallingConvention::CC_CDECL:
			case CallingConvention::CC_STDCALL:
			case CallingConvention::CC_PASCAL:
			case CallingConvention::CC_FASTCALL:
			case CallingConvention::CC_THISCALL:
				return RETURN_VALUE_PASSED_THROUGH_ST0;
			case CallingConvention::CC_WATCOM:
				return INCONSISTENT_CALLING_CONVENTION;
			case CallingConvention::CC_UNKNOWN:
				// in this case we know that 32bit arch. almost for sure pass return in ST0
				return RETURN_VALUE_PASSED_THROUGH_ST0;
			default:
				return UNKNOWN_CALLING_CONVENTION; // some other call canvention witch we dont know
		}
	}
	else // x86-64bit architecture
	{
		return EMPTY_FPU_STACK; // returned through XMM0
	}
}

int X87FpuAnalysis::expectedTopBasedOnRestOfBlock(llvm::BasicBlock* currentBb)
{
	for (auto & restOfBlock : *currentBb)
	{
		Instruction *j = &restOfBlock;
		auto *add = dyn_cast<AddOperator>(j);
		auto *sub = dyn_cast<SubOperator>(j);
		auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(j);
		auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(j);
		if (sub	&& isa<ConstantInt>(sub->getOperand(1)))
		{
			return EMPTY_FPU_STACK;
		}
		else if (callLoad || (add && isa<ConstantInt>(add->getOperand(1))))
		{
			return RETURN_VALUE_PASSED_THROUGH_ST0;
		}
		else if (callStore)
		{
			return INCORRECT_STACK_OPERATION;
		}
		else {continue;} // some not interesting instructions -> skip
	}
	return EMPTY_FPU_STACK;
}

bool X87FpuAnalysis::analyzeFunctionReturn(
	llvm::Function& function,
	int topVal,
	std::map<llvm::GlobalValue::GUID, int>& resultOfAnalyze)
{
	auto callConv = expectedTopBasedOnCallingConvention(function);

	if (callConv == EMPTY_FPU_STACK && topVal == EMPTY_FPU_STACK)
	{
		resultOfAnalyze[function.getGUID()] = topVal;
	}
	else if (callConv == EMPTY_FPU_STACK && topVal != EMPTY_FPU_STACK)
	{
		return false; // calling convention expect empty FPU stack and it is not
	}
	else if (callConv == RETURN_VALUE_PASSED_THROUGH_ST0
			 && topVal == RETURN_VALUE_PASSED_THROUGH_ST0)
	{
		resultOfAnalyze[function.getGUID()] = topVal;
	}
	else if (callConv == RETURN_VALUE_PASSED_THROUGH_ST0
			 && topVal == EMPTY_FPU_STACK)
	{	// calling convention expect return value in ST0 but it is not a function with float return value
		resultOfAnalyze[function.getGUID()] = topVal;
	}
	else if (callConv == RETURN_VALUE_PASSED_THROUGH_ST0
			 && (topVal != EMPTY_FPU_STACK || topVal != RETURN_VALUE_PASSED_THROUGH_ST0))
	{
		return false; // calling conv expect empty fpu stack or stO but there is pushed more then st0
	}
	else if (callConv == INCONSISTENT_CALLING_CONVENTION || topVal == INCORRECT_STACK_OPERATION)
	{
		return false; // not possible analyze
	}
	else // UNKNOWN_CALLING_CONVENTION -> so we predict
	{
		resultOfAnalyze[function.getGUID()] = topVal;
	}

	return true; // analyze success
}

bool X87FpuAnalysis::analyzeInstruction(Instruction& i, std::map<llvm::Value*, int>& topVals, int& topVal)
{
	auto *callFunction = dyn_cast<CallInst>(&i);
	auto *loadFpuTop = dyn_cast<LoadInst>(&i);
	auto *storeFpuTop = dyn_cast<StoreInst>(&i);
	auto *add = dyn_cast<AddOperator>(&i);
	auto *sub = dyn_cast<SubOperator>(&i);
	auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(&i);
	auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(&i);
	auto *branch = dyn_cast<BranchInst>(&i);

	// read actual value of fpu top
	if (loadFpuTop && loadFpuTop->getPointerOperand() == top)
	{
		topVals[&i] = topVal;

		LOG << "\t\t" << AsmInstruction(&i).getAddress()
			<< " @ " << std::dec << topVal << std::endl;
	}
	// store actual value of fpu top
	else if (storeFpuTop && storeFpuTop->getPointerOperand() == top
			&& topVals.find(storeFpuTop->getValueOperand()) != topVals.end())
	{
		topVal = topVals.find(storeFpuTop->getValueOperand())->second;

		LOG << "\t\t" << AsmInstruction(&i).getAddress()
			<< " @ " << std::dec << topVal << std::endl;
	}
	// function call -> possible change value of fpu top
	else if (callFunction && !callStore && !callLoad)
	{
		if (topVal != EMPTY_FPU_STACK)
		{
			return ANALYZE_FAIL; //stack must be empty before function call
		}

		auto* function = _module->getFunction(callFunction->getCalledValue()->getName().str());
		if (!function)
		{
			return ANALYZE_FAIL;
		}

		if (analyzedFunctions.find(function->getGUID()) != analyzedFunctions.end())
		{	// if caller definition is already analyzed then we know value of top after call
			topVals[&i] = topVal = analyzedFunctions[function->getGUID()];
		}
		else// if caller definition is not analyzed then we analyze rest of block after call and implicate
		{	// value of top, then in future we will compare out expected top with analyzed top
			if (!analyzeFunctionReturn(*function, expectedTopBasedOnRestOfBlock(i.getParent()),
			 calledButNotAnalyzedFunctions))
			{
				return ANALYZE_FAIL;
			}
			topVals[&i] = topVal = calledButNotAnalyzedFunctions[function->getGUID()];
		}
	}
	// increment fpu top
	else if (add && topVals.find(add->getOperand(0)) != topVals.end() && isa<ConstantInt>(add->getOperand(1)))
	{
		int oldTopValue = topVals.find(add->getOperand(0))->second;
		int constValue = cast<ConstantInt>(add->getOperand(1))->getZExtValue();//it should be 1
		int newTopValue = oldTopValue + constValue;
		if (newTopValue > 8) // attempt to pop value from empty FPU stack
		{
			LOG << "\t\t\t" << "undeflow of fpu top " << oldTopValue << " -> " << newTopValue << std::endl;
			return ANALYZE_FAIL;
		}
		topVals[&i] = newTopValue;

		LOG << "\t\t" << AsmInstruction(&i).getAddress() << std::dec
			<< " @ " << oldTopValue << " - " << constValue << " = "
			<< newTopValue << std::endl;
	}
	// decrement fpu top
	else if (sub && topVals.find(sub->getOperand(0)) != topVals.end()&& isa<ConstantInt>(sub->getOperand(1)))
	{
		int oldTopValue = topVals.find(sub->getOperand(0))->second;
		int constValue = cast<ConstantInt>(sub->getOperand(1))->getZExtValue();//it should be 1
		int newTopValue = oldTopValue - constValue;
		if (newTopValue < 0)
		{
			LOG << "\t\t\t" << "undeflow of fpu top " << oldTopValue << " -> " << newTopValue << std::endl;
			return ANALYZE_FAIL;
		}
		topVals[&i] = newTopValue;

		LOG << "\t\t" << AsmInstruction(&i).getAddress() << std::dec
			<< " @ " << oldTopValue << " - " << constValue << " = "
			<< newTopValue << std::endl;
	}
	// pseudo load/store of fpu top
	else if ((callStore && topVals.find(callStore->getArgOperand(0)) != topVals.end())
	|| (callLoad && topVals.find(callLoad->getArgOperand(0)) != topVals.end()))
	{
		CallInst *pseudoCall;
		uint32_t regBase;
		if (callStore)
		{
			pseudoCall = callStore;
			regBase = _config->isLlvmX87DataStorePseudoFunctionCall(pseudoCall)
				  ? uint32_t(X86_REG_ST0) : uint32_t(X87_REG_TAG0);
		}
		else // callLoad
		{
			pseudoCall = callLoad;
			regBase = _config->isLlvmX87DataLoadPseudoFunctionCall(pseudoCall)
					  ? uint32_t(X86_REG_ST0) : uint32_t(X87_REG_TAG0);
		}

		// st(0) == TOP(7) ... st(7) == TOP(0) => st(X) = 7 - TOP(X)
		int relativeIndexOfRegister = 7 - topVals.find(pseudoCall->getArgOperand(0))->second;

		if (0 > relativeIndexOfRegister || relativeIndexOfRegister > 7)
		{
			return ANALYZE_FAIL; // attempt to access to FPU register with index which doesnt exist
		}

		uint32_t absoluteIndexOfRegister = regBase + relativeIndexOfRegister;
		auto *reg = _abi->getRegister(absoluteIndexOfRegister);

		LOG << "\t\t\t" << "load/store -- " << reg->getName().str() << std::endl;

		//pseudo call will be replaced by store/load of concrete register but only if whole analyze succed
		instToChange.push_back(std::make_pair(reg, &i));
	}
	else if (branch)
	{
		for (unsigned i = 1; i < branch->getNumOperands(); i++)
		{
			nestedBlocksQueue.push({branch->getOperand(i), topVal});
		}
	}
	else if (callStore || callLoad)
	{
		LOG << "\t\t" << AsmInstruction(&i).getAddress() << " @ "
			<< llvmObjToString(&i) << std::endl;
		assert(false && "some other pattern");
		return ANALYZE_FAIL;
	}

	return ANALYZE_SUCCESS;
}

bool X87FpuAnalysis::analyzeBasicBlock(
	std::map<llvm::Value*, int>& topVals,
	llvm::BasicBlock* bb,
	int& topVal)
{
	LOG << "\t" << bb->getName().str() << std::endl;

	for (auto & it : *bb)
	{
		if (!analyzeInstruction(it, topVals, topVal))
		{
			return ANALYZE_FAIL;
		}
	}

	return ANALYZE_SUCCESS;
}

void X87FpuAnalysis::optimizeAnalyzedFpuInstruction()
{
	for (auto& i : instToChange)
	{
		auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(i.second);
		auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(i.second);
		if (callStore)
		{
			new StoreInst(callStore->getArgOperand(1), i.first, callStore);
			callStore->eraseFromParent();
		}
		if (callLoad)
		{
			auto *lTmp = new LoadInst(i.first, "", callLoad);
			auto *conv = IrModifier::convertValueToType(lTmp, callLoad->getType(), callLoad);
			callLoad->replaceAllUsesWith(conv);
			callLoad->eraseFromParent();
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
