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
		unsigned index = 0;
		FunctionAnalyzeMetadata metadata(*f);
		for (Function::iterator it = f->begin(), end = f->end(); it != end; ++it)
		{
			BasicBlock* bb = it.operator->();
			Instruction& endInst = bb->getInstList().back();
			if (dyn_cast<ReturnInst>(&endInst)) //it is terminating block
			{
				metadata.terminatingBasicBlocks.push_back(bb);
			}
			metadata.indexes[bb][FunctionAnalyzeMetadata::inIndex] = index;
			metadata.indexes[bb][FunctionAnalyzeMetadata::outIndex] = index+1;
			index += 2;
		}
		functionsMetadata.push_back(metadata);
	}

	return functionsMetadata;
}


int matrixRank(cv::Mat& mat)
{
	float treshHold = 0.0001;
	cv::Mat singularValues;
	cv::SVD::compute(mat, singularValues);
	singularValues = cv::abs(singularValues);
	return cv::countNonZero(singularValues > treshHold);
}

bool consistenSystem(cv::Mat& A, cv::Mat& B)
{
	int rankA = matrixRank(A);

	cv::Mat augmented;
	cv::hconcat(A, B, augmented);
	int rankAugmentedA = matrixRank(augmented);

	return (rankA == rankAugmentedA);
}

void FunctionAnalyzeMetadata::addEquation(std::list<std::tuple<llvm::BasicBlock&,int,IndexType >> vars, int result)
{
	cv::Mat rowA = cv::Mat_<float>::zeros(1, 2*function.size());
	cv::Mat rowB = cv::Mat_<float>(1,1) << result;
	for (auto var : vars)
	{
		rowA.at<float>(0, indexes[&std::get<0>(var)][std::get<2>(var)]) = std::get<1>(var);
	}
	A.push_back(rowA);
	B.push_back(rowB);
	numberOfEquations++;
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

	for (auto& funMd: analyzedFunctionsMetadata)
	{
		BasicBlock& enterBlock = funMd.function.begin().operator*();
		funMd.addEquation({{enterBlock, 1, funMd.inIndex}}, 8);

		for (Function::iterator bbIt=funMd.function.begin(),
		 	bbEndIt = funMd.function.end(); bbIt != bbEndIt; ++bbIt)
		{
			BasicBlock* bb = bbIt.operator->();
			int outTop=0;

			if (!analyzeBasicBlock(funMd, bb, outTop))
			{
				funMd.analyzeSuccess = false;
			}
			if (std::find(funMd.terminatingBasicBlocks.begin(), funMd.terminatingBasicBlocks.end(), bb) != funMd.terminatingBasicBlocks.end())
			{
				funMd.addEquation({{*bb, 1, funMd.outIndex}}, 8+outTop);
			}

			funMd.addEquation({{*bb, -1, funMd.inIndex},{*bb, 1, funMd.outIndex}}, outTop);

			for (auto it = pred_begin(bb), et=pred_end(bb); it != et; ++it)
			{
				BasicBlock *pred = it.operator*();
				funMd.addEquation({{*bb, 1, funMd.inIndex},{*pred, -1, funMd.outIndex}}, 0);
			}
		}

		if (!consistenSystem(funMd.A, funMd.B))
		{
			funMd.analyzeSuccess = false;
		}
		cv::solve(funMd.A, funMd.B, funMd.x, cv::DECOMP_SVD);
		funMd.x.convertTo(funMd.x, CV_32S);
	}

	return optimizeAnalyzedFpuInstruction();
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
			int inputIndex = funMd.indexes[bb][funMd.inIndex];
			int outputIndex = funMd.indexes[bb][funMd.outIndex];
			std::cerr << bb->getName().str()<<":";
			std::cerr << " (in=" << funMd.x.at<int>(inputIndex, 0);;
			std::cerr << ",out=" << funMd.x.at<int>(outputIndex, 0) << ")\n";
		}
	}
}

int X87FpuAnalysis::expectedTopBasedOnCallingConvention(llvm::Instruction& inst)
{
	Function* f = inst.getParent()->getParent();
	auto configFunctionMetadata = _config->getConfig().functions.getFunctionByName(f->getName());
	if (!configFunctionMetadata)
	{
		return 0;
	}

	if (_config->getConfig().architecture.isX86_16())
	{
		return 0;
	}
	else if (_config->getConfig().architecture.isX86_32())
	{
		return expectedTopBasedOnRestOfBlock(inst);
	}
	else // x86-64bit architecture
	{
		return 0;
	}
}

int X87FpuAnalysis::expectedTopBasedOnRestOfBlock(llvm::Instruction& analyzedInstr)
{
	BasicBlock* bb = analyzedInstr.getParent();
	for (BasicBlock::iterator it = bb->begin(), e = bb->end(); it != e; ++it)
	{
		Instruction* inst = it.operator->();
		if (inst == &analyzedInstr)
		{
			while (it != e)
			{
				inst = it.operator->();
				auto *add = dyn_cast<AddOperator>(inst);
				auto *sub = dyn_cast<SubOperator>(inst);
				auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(inst);
				if (sub	&& isa<ConstantInt>(sub->getOperand(1)))
				{
					return 0;
				}
				else if (callLoad || (add && isa<ConstantInt>(add->getOperand(1))))
				{
					return -1;
				}
				++it;
			}
		}
	}

	return 0;
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
		outTop = expectedTopBasedOnCallingConvention(i);
		topVals.push_back(outTop);
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

bool X87FpuAnalysis::optimizeAnalyzedFpuInstruction()
{
	bool analyzeSucces = true;
	for (auto& fun : analyzedFunctionsMetadata)
	{
		if (!fun.analyzeSuccess)
		{
			analyzeSucces = false;
			continue;
		}
		for (auto& i : fun.pseudoCalls)
		{
			auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(&i.second);
			auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(&i.second);
			int registerIndex = i.first + 7 - fun.x.at<int>(fun.indexes[i.second.getParent()][fun.inIndex], 0);
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

	return analyzeSucces;
}

} // namespace bin2llvmir
} // namespace retdec
