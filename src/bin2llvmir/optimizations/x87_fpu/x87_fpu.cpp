/**
* @file src/bin2llvmir/optimizations/x87_fpu/x87_fpu.cpp
* @brief x87 FPU analysis - replace fpu stack operations with FPU registers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/CFG.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Operator.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/ADT/DepthFirstIterator.h>
#include <llvm/ADT/BreadthFirstIterator.h>

#include "retdec/bin2llvmir/optimizations/x87_fpu/x87_fpu.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

#include <libalglib/ap.h>
#include <opencv2/core.hpp>

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

void FunctionAnalyzeMetadata::fillRow(
	unsigned& row,
	std::vector<std::pair<std::string,int>> block)
{
	int col;
	for (unsigned i = 0; i < block.size(); ++i)
	{
		col = colIndex[block[i].first];
		A.at<float>(row, col) = block[i].second;
	}
	++row;
}

std::list<FunctionAnalyzeMetadata> X87FpuAnalysis::getFunctions2Analyze()
{
	std::list<Function*> functions;
	for (Value::use_iterator k = top->use_begin(); k != top->use_end(); ++k)
	{
		if (Instruction *ins= dyn_cast<Instruction>(k->getUser()))
		{
			functions.push_back(ins->getParent()->getParent());
		}
	}
	functions.unique();

	std::list<FunctionAnalyzeMetadata> functionsMetadata;
	for (auto &f : functions)
	{
		FunctionAnalyzeMetadata metadata(*f);
		functionsMetadata.push_back(metadata);
	}

	return functionsMetadata;
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

	analyzedFunctionsMetadata = getFunctions2Analyze();

	// 2 rows are by default because we know 2 equations -> value of top at the begining and at the end
	unsigned rows = 2,
	cols = 0;
	for (auto& funMd: analyzedFunctionsMetadata)
	{
		for (Function::iterator funIt = funMd.function.begin(),
		 	endIt = funMd.function.end(); funIt != endIt; ++funIt)
		{
			BasicBlock* bb = funIt.operator->();

			funMd.colIndex[bb->getName().str() + "_in"] = cols;
			funMd.colIndex[bb->getName().str() + "_out"] = cols + 1;

			cols += 2;
			rows += 1 + pred_size(bb);
		}

		funMd.A = cv::Mat_<float>::zeros(rows, cols);
		funMd.B = cv::Mat_<float>::zeros(rows, 1);
		funMd.x = cv::Mat_<float>::zeros(rows,1);

		unsigned rowIndex = 0;

		for (Function::iterator bbIt=funMd.function.begin(),
		 	bbEndIt = funMd.function.end(); bbIt != bbEndIt; ++bbIt)
		{
			BasicBlock* bb = bbIt.operator->();
			int outTop=0;

			if (!analyzeBasicBlock(funMd, bb, outTop))
			{
				continue;//analyze fail => genout comment and skip rest of this block
			}

			funMd.B.at<float>(0, rowIndex) = outTop;
			auto inBlock = std::make_pair(bb->getName().str()+"_in", -1);
			auto outBlock = std::make_pair(bb->getName().str()+"_out", 1);
			funMd.fillRow(rowIndex, {inBlock, outBlock});

			for (auto it = pred_begin(bb), et=pred_end(bb); it != et; ++it)
			{
				BasicBlock *pred = it.operator*();
				auto inBlock = std::make_pair(bb->getName().str()+"_in", 1);
				auto outBlock = std::make_pair(pred->getName().str()+"_out", -1);
				funMd.fillRow(rowIndex, {inBlock, outBlock});
			}
		}

		std::string firstBlockName = funMd.function.front().getName().str() + "_in";
		std::string lastBlockName = funMd.function.back().getName().str()+"_out";
		funMd.B.at<float>(0, rowIndex) = 8;
		funMd.fillRow(rowIndex, {{firstBlockName, 1}});
		int bbOut;
		if (analyzedFunctions.find(funMd.function.getGUID()) != analyzedFunctions.end())
		{	// if caller definition is already analyzed then we know value of top after call
			bbOut = analyzedFunctions[funMd.function.getGUID()];
		}
		else
		{
			int t = expectedTopBasedOnRestOfFunction(&funMd.function.back());
			if (!analyzeFunctionReturn(funMd.function, t,
									   analyzedFunctions))
			{
				return ANALYZE_FAIL;
			}
			bbOut = analyzedFunctions[funMd.function.getGUID()];
		}
		funMd.B.at<float>(0, rowIndex) = bbOut;
		funMd.fillRow(rowIndex, {{lastBlockName, 1}});


		cv::solve(funMd.A, funMd.B, funMd.x, cv::DECOMP_SVD);
		funMd.x.convertTo(funMd.x, CV_32S);
	}
	printBlocksAnalyzeResult();

	optimizeAnalyzedFpuInstruction();
	return ANALYZE_SUCCESS;
}

void X87FpuAnalysis::printBlocksAnalyzeResult()
{
	std::cerr << "A*x=B\n";
	for (auto& funMd: analyzedFunctionsMetadata)
	{
		std::cerr << funMd.function.getName().str() <<std::endl;
		std::cerr << "A=\n" << funMd.A << "\nx=\n" << funMd.x << "\nB=\n" << funMd.B << "\n";
		for (Function::iterator functionI=funMd.function.begin(),
			e = funMd.function.end(); functionI != e; ++functionI)
		{
			BasicBlock* bb = functionI.operator->();
			int inputIndex = funMd.colIndex[bb->getName().str()+"_in"];
			int outputIndex = funMd.colIndex[bb->getName().str()+"_out"];
			std::cerr << bb->getName().str()<<":";
			std::cerr << " (in=" << funMd.x.at<int>(inputIndex, 0);;
			std::cerr << ",out=" << funMd.x.at<int>(outputIndex, 0) << ")\n";
		}
	}
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

int X87FpuAnalysis::expectedTopBasedOnRestOfFunction(llvm::BasicBlock* currentBb)
{
	int callConv = expectedTopBasedOnCallingConvention(*currentBb->getParent());
	int top = EMPTY_FPU_STACK;
	for (auto & restOfBlock : *currentBb)
	{
		Instruction *j = &restOfBlock;
		auto *add = dyn_cast<AddOperator>(j);
		auto *sub = dyn_cast<SubOperator>(j);
		if (sub	&& isa<ConstantInt>(sub->getOperand(1)))
		{
			--top;
		}
		else if (add && isa<ConstantInt>(add->getOperand(1)))
		{
			++top;
		}
		else {continue;} // some not interesting instructions -> skip
	}

	if ((top == EMPTY_FPU_STACK && callConv == EMPTY_FPU_STACK)
		|| (top == RETURN_VALUE_PASSED_THROUGH_ST0 && callConv == RETURN_VALUE_PASSED_THROUGH_ST0))
	{
		return top; // return fp value or not
	}
	else
	{
		return EMPTY_FPU_STACK; // top > 8 -> beacuse we assume that block begin at 8 but we dont know -> empty
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

bool X87FpuAnalysis::analyzeInstruction(
	FunctionAnalyzeMetadata& funMd,
	Instruction& i,
	std::list<int>& topVals,
	int& outTop)
{
	auto *callFunction = dyn_cast<CallInst>(&i);
	auto *loadFpuTop = dyn_cast<LoadInst>(&i);
	auto *storeFpuTop = dyn_cast<StoreInst>(&i);
	auto *add = dyn_cast<AddOperator>(&i);
	auto *sub = dyn_cast<SubOperator>(&i);
	auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(&i);
	auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(&i);

	// read actual value of fpu top
	if (loadFpuTop && loadFpuTop->getPointerOperand() == top)
	{
		if (topVals.empty())
		{
			topVals.push_back(0); // init FPU TOP with zero
		}
		outTop = topVals.back();
	}
	// store actual value of fpu top
	else if (storeFpuTop && storeFpuTop->getPointerOperand() == top)
	{
		if (topVals.empty())
		{
			return ANALYZE_FAIL;
		}
		outTop = topVals.back();
	}
	// function call -> possible change value of fpu top
	else if (callFunction && !callStore && !callLoad)
	{
		auto* function = _module->getFunction(callFunction->getCalledValue()->getName().str());
		if (!function)
		{
			return ANALYZE_FAIL;
		}

		if (analyzedFunctions.find(function->getGUID()) != analyzedFunctions.end())
		{	// if caller definition is already analyzed then we know value of top after call
			outTop = analyzedFunctions[function->getGUID()] - 8;
			topVals.push_back(outTop);
		}
		else// if caller definition is not analyzed then we analyze rest of block after call and implicate
		{	// value of top, then in future we will compare out expected top with analyzed top
			if (!analyzeFunctionReturn(*function, expectedTopBasedOnRestOfBlock(i.getParent()),
			 calledButNotAnalyzedFunctions))
			{
				return ANALYZE_FAIL;
			}
			outTop = calledButNotAnalyzedFunctions[function->getGUID()] - 8;
			topVals.push_back(outTop);
		}
	}
	// increment fpu top
	else if (add && isa<ConstantInt>(add->getOperand(1)))
	{
		int oldTopValue = topVals.back();
		int constValue = cast<ConstantInt>(add->getOperand(1))->getZExtValue();//it should be 1
		int newTopValue = oldTopValue + constValue;
		outTop = newTopValue;
		topVals.push_back(outTop);
	}
	// decrement fpu top
	else if (sub && isa<ConstantInt>(sub->getOperand(1)))
	{
		int oldTopValue = topVals.back();
		int constValue = cast<ConstantInt>(sub->getOperand(1))->getZExtValue();//it should be 1
		int newTopValue = oldTopValue - constValue;
		outTop = newTopValue;
		topVals.push_back(outTop);
	}
	// pseudo load/store of fpu top
	else if (callStore || callLoad)
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
		int relativeIndexOfRegister = outTop*(-1);

		uint32_t absoluteIndexOfRegister = regBase + relativeIndexOfRegister;

		//pseudo call will be replaced by store/load of concrete register but only if whole analyze succed
		funMd.pseudoCalls.push_back({absoluteIndexOfRegister, i});
	}

	return ANALYZE_SUCCESS;
}

bool X87FpuAnalysis::analyzeBasicBlock(
	FunctionAnalyzeMetadata& funMd,
	llvm::BasicBlock* bb,
	int& outTop)
{
	std::list<int> topVals;
	for (BasicBlock::iterator it = bb->begin(), e = bb->end(); it != e; ++it)
	{
		Instruction& inst = it.operator*();
		if (!analyzeInstruction(funMd, inst, topVals, outTop))
		{
			return ANALYZE_FAIL;
		}
	}

	return ANALYZE_SUCCESS;
}

void X87FpuAnalysis::optimizeAnalyzedFpuInstruction()
{
	for (auto& fun : analyzedFunctionsMetadata)
	{
		for (auto& i : fun.pseudoCalls)
		{
			auto name =  i.second.getParent()->getName().str()+"_in";
			auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(&i.second);
			auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(&i.second);
			int registerIndex = std::get<0>(i) + 7 - fun.x.at<int>(fun.colIndex[name], 0);
			auto *reg = _abi->getRegister(registerIndex);
			if (!reg)
			{
				continue; // analyze fail -> skip
			}

			if (callStore)
			{
				new StoreInst(callStore->getArgOperand(1), reg, callStore);
				callStore->eraseFromParent();
			}
			if (callLoad)
			{
				auto *lTmp = new LoadInst(reg, "", callLoad);
				auto *conv = IrModifier::convertValueToType(lTmp, callLoad->getType(), callLoad);
				callLoad->replaceAllUsesWith(conv);
				callLoad->eraseFromParent();
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
