/**
* @file src/bin2llvmir/optimizations/x87_fpu/x87_fpu.cpp
* @brief x87 FPU analysis - replace fpu stack operations with FPU registers.
* @copyright (c) 2020 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/CFG.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Operator.h>

#include <Eigen/Core>
#include <Eigen/QR>

#include "retdec/utils/io/log.h"
#include "retdec/bin2llvmir/optimizations/x87_fpu/x87_fpu.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false

#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/capstone2llvmir/x86/x86.h"

using namespace llvm;
using namespace retdec::bin2llvmir::llvm_utils;
using namespace retdec::utils::io;

namespace retdec {
namespace bin2llvmir {

int augmentedRank(Eigen::MatrixXd &A, Eigen::MatrixXd &B)
{
	A.conservativeResize(Eigen::NoChange, A.cols()+1);
	A.col(A.cols()-1) = B;

	int rankAugmentedA = A.colPivHouseholderQr().rank();

	A.conservativeResize(Eigen::NoChange, A.cols()-1);

	return rankAugmentedA;
}

class FunctionAnalyzeMetadata
{
	public:

		bool analyzeSuccess = true;
		enum IndexType {
			inIndex, outIndex
		};

		llvm::Function& function;
		std::map<llvm::BasicBlock*, std::map<IndexType,unsigned >> indexes;

		std::list<llvm::BasicBlock*> terminatingBasicBlocks;
		// A * x = B
		Eigen::MatrixXd A;
		Eigen::MatrixXd B;
		Eigen::MatrixXd x;

		int numberOfEquations = 0;

		// 1. index to register, 2.pseudo instruction
		std::list<std::pair<uint32_t ,llvm::Instruction*>> pseudoCalls;
		std::map<llvm::Value*, int> topVals;

		int expectedTop = 0;
		bool expectedTopAnalyzed = false;
		std::set<llvm::Function*> calledFunctions;

	void initSystem();
	void addEquation(const std::list<std::tuple<llvm::BasicBlock&,int,IndexType >>& vars, int result);
	FunctionAnalyzeMetadata(llvm::Function &function1) : function(function1) {};

};

char X87FpuAnalysis::ID = 0;

static RegisterPass<X87FpuAnalysis> X(
		"retdec-x87-fpu",
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

std::list<FunctionAnalyzeMetadata> getFunctions2Analyze(llvm::GlobalVariable* top)
{
	std::list<Function*> functions;
	for (Value::use_iterator k = top->use_begin(); k != top->use_end(); ++k)
	{
		if (Instruction *ins= dyn_cast<Instruction>(k->getUser()))
		{
			functions.push_back(ins->getParent()->getParent());
		}
	}
	functions.sort();
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

void FunctionAnalyzeMetadata::initSystem()
{
	unsigned matrixLen = 1;// + terminatingBasicBlocks.size();
	for (Function::iterator bbIt=function.begin(), bbEndIt = function.end(); bbIt != bbEndIt; ++bbIt)
	{
		BasicBlock* bb = bbIt.operator->();
		matrixLen += 1 + pred_size(bb);
	}
	A.resize(matrixLen, 2*function.size());
	B.resize(matrixLen, 1);
	A.setZero();
	B.setZero();
}

void FunctionAnalyzeMetadata::addEquation(const std::list<std::tuple<llvm::BasicBlock&,int,IndexType >>& vars, int result)
{
	B(numberOfEquations, 0) = result;
	for (auto var : vars)
	{
		A(numberOfEquations, indexes[&std::get<0>(var)][std::get<2>(var)]) = std::get<1>(var);
	}

	numberOfEquations++;
}

bool X87FpuAnalysis::checkArchAndCallConvException(llvm::Function* fun)
{
	using CallingConvention = common::CallingConvention::eCC;

	auto configFunctionMetadata = _config->getConfig().functions.getFunctionByName(fun->getName());
	if (!configFunctionMetadata)
		return false;

	auto convention = configFunctionMetadata->callingConvention.getID();

	if (_config->getConfig().architecture.isX86_16() || _config->getConfig().architecture.isX86_32())
	{
		switch (convention)
		{
			case CallingConvention::CC_CDECL:
			case CallingConvention::CC_STDCALL:
			case CallingConvention::CC_PASCAL:
			case CallingConvention::CC_FASTCALL:
			case CallingConvention::CC_THISCALL:
			case CallingConvention::CC_UNKNOWN:
			default:
				return true;
			case CallingConvention::CC_WATCOM:
				return false; //inconsisten
		}
	}
	else // x86-64bit architecture
	{
		return false;
	}
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

	auto analyzedFunctionsMetadata = getFunctions2Analyze(top);

	for (auto& funMd: analyzedFunctionsMetadata)
	{
		funMd.initSystem();
		BasicBlock& enterBlock = funMd.function.begin().operator*();
		funMd.addEquation({{enterBlock, 1, funMd.inIndex}}, EMPTY_FPU_STACK);

		for (Function::iterator bbIt=funMd.function.begin(),
			bbEndIt = funMd.function.end(); bbIt != bbEndIt; ++bbIt)
		{
			BasicBlock* bb = bbIt.operator->();
			int relativeOutBbTop = 0;

			if (!analyzeBasicBlock(analyzedFunctionsMetadata, funMd, bb, relativeOutBbTop))
			{
				funMd.analyzeSuccess = false;
			}

			funMd.addEquation({{*bb, -1, funMd.inIndex},{*bb, 1, funMd.outIndex}}, relativeOutBbTop);

			//if (_config->getConfig().architecture.isX86_16() || _config->getConfig().architecture.isX86_64()
			//	&& std::find(funMd.terminatingBasicBlocks.begin(), funMd.terminatingBasicBlocks.end(), bb) != funMd.terminatingBasicBlocks.end())
			//{
			//	funMd.addEquation({{*bb, 1, funMd.outIndex}}, EMPTY_FPU_STACK);
			//}

			for (auto it = pred_begin(bb), et=pred_end(bb); it != et; ++it)
			{
				BasicBlock *pred = it.operator*();
				funMd.addEquation({{*bb, 1, funMd.inIndex},{*pred, -1, funMd.outIndex}}, 0);
			}
		}

		if (funMd.A.rows() <= PERFORMANCE_CEIL)
		{
			const auto& pivHouseholderQr = funMd.A.colPivHouseholderQr();
			int matRank = pivHouseholderQr.rank();
			int augmentedMatRank = augmentedRank(funMd.A, funMd.B);

			if (matRank == augmentedMatRank) // there is exactly one solution
			{
				funMd.x = pivHouseholderQr.solve(funMd.B);
			}
			else
			{
				funMd.analyzeSuccess = false;
			}
		}
		else // worst scenario => due to performance ceil turn to simple no CFG analyse
		{
			int height = funMd.A.rows();
			funMd.x.resize(height, 1);
			for (int i = 0; i < height; ++i)
			{
				funMd.x(i, 0) = EMPTY_FPU_STACK;
			}
		}
	}

	return optimizeAnalyzedFpuInstruction(analyzedFunctionsMetadata);
}

std::list<FunctionAnalyzeMetadata>::iterator X87FpuAnalysis::getFunMd(
		std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
		llvm::Function* fun)
{
	std::list<FunctionAnalyzeMetadata>::iterator it;
	for (it = analyzedFunctionsMetadata.begin(); it != analyzedFunctionsMetadata.end(); ++it)
	{
		auto& funMd = it.operator*();
		if (&funMd.function == fun)
		{
			return it;
		}
	}

	return analyzedFunctionsMetadata.end();
}

bool X87FpuAnalysis::analyzeInstruction(
		std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
		FunctionAnalyzeMetadata& funMd,
		Instruction* i,
		int& outTop)
{
	auto *callFunction = dyn_cast<CallInst>(i);
	auto *loadFpuTop = dyn_cast<LoadInst>(i);
	auto *storeFpuTop = dyn_cast<StoreInst>(i);
	auto *add = dyn_cast<AddOperator>(i);
	auto *sub = dyn_cast<SubOperator>(i);
	auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(i);
	auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(i);

	// read actual value of fpu top
	if (loadFpuTop && loadFpuTop->getPointerOperand() == top)
	{
		funMd.topVals[i] = outTop;
	}
	// store actual value of fpu top
	else if (storeFpuTop && storeFpuTop->getPointerOperand() == top && funMd.topVals.find(storeFpuTop->getValueOperand()) != funMd.topVals.end())
	{
		outTop = funMd.topVals.find(storeFpuTop->getValueOperand())->second;
	}
	// function call -> possible change value of fpu top
	else if (callFunction && !callStore && !callLoad && !callFunction->getCalledFunction()->isIntrinsic())
	{
		auto it = getFunMd(
				analyzedFunctionsMetadata,
				callFunction->getCalledFunction()
		);

		if (it != analyzedFunctionsMetadata.end())
		{
			auto& fun = it.operator*();
			if (fun.expectedTopAnalyzed)
			{
				outTop += fun.expectedTop;
			}
			else
			{
				outTop += expectedTopBasedOnRestOfBlock(analyzedFunctionsMetadata, *i);
			}
		}
		else // some library function e.g "roundf()"
		{
			outTop += expectedTopBasedOnRestOfBlock(analyzedFunctionsMetadata, *i);
		}
	}
	// increment fpu top
	else if (add && isa<ConstantInt>(add->getOperand(1)) && funMd.topVals.find(add->getOperand(0)) != funMd.topVals.end())
	{
		//auto *op0 = dyn_cast<Instruction>(add->getOperand(0));
		int oldTopValue = funMd.topVals.find(add->getOperand(0))->second;
		int constValue = cast<ConstantInt>(add->getOperand(1))->getZExtValue();//it should be 1
		int newTopValue = oldTopValue + constValue;
		funMd.topVals[i] = newTopValue;
	}
	// decrement fpu top
	else if (sub && isa<ConstantInt>(sub->getOperand(1)) && funMd.topVals.find(sub->getOperand(0)) != funMd.topVals.end())
	{
		//auto *op0 = dyn_cast<Instruction>(sub->getOperand(0));
		int oldTopValue = funMd.topVals.find(sub->getOperand(0))->second;
		int constValue = cast<ConstantInt>(sub->getOperand(1))->getZExtValue();//it should be 1
		int newTopValue = oldTopValue - constValue;
		funMd.topVals[i] = newTopValue;
	}
	// pseudo load/store of fpu top
	else if (callStore || callLoad)
	{
		//pseudo call will be replaced by store/load of concrete register but only if whole analyze succed
		int tmp;
		if (callStore && funMd.topVals.find(callStore->getArgOperand(0)) != funMd.topVals.end())
		{
			tmp = funMd.topVals.find(callStore->getArgOperand(0))->second;
		}
		else if (callLoad && funMd.topVals.find(callLoad->getArgOperand(0)) != funMd.topVals.end())
		{
			tmp = funMd.topVals.find(callLoad->getArgOperand(0))->second;
		}
		else
		{
			return ANALYZE_FAIL;
		}

		funMd.pseudoCalls.push_back({tmp, i});
	}

	return ANALYZE_SUCCESS;
}

int X87FpuAnalysis::expectedTopBasedOnRestOfBlock(
		std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
		llvm::Instruction& analyzedInstr)
{
	if (!checkArchAndCallConvException(analyzedInstr.getParent()->getParent()))
	{
		return NOP_FPU_STACK;
	}

	std::map<llvm::Value*, bool> topVals;
	BasicBlock* bb = analyzedInstr.getParent();
	Instruction *next = analyzedInstr.getNextNode();

	if (!next || next->getParent() != bb)
	{
		return NOP_FPU_STACK;
	}

	for (BasicBlock::iterator it = next->getIterator(), e = bb->end(); it != e; ++it)
	{
		Instruction *i = it.operator->();
		auto *loadFpuTop = dyn_cast<LoadInst>(i);
		auto *sub = dyn_cast<SubOperator>(i);
		auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(i);
		auto *callFunction = dyn_cast<CallInst>(i);

		if (loadFpuTop && loadFpuTop->getPointerOperand() == top)
		{
			topVals[i] = true;
		}
		else if (sub && isa<ConstantInt>(sub->getOperand(1)) && topVals.find(sub->getOperand(0)) != topVals.end())
		{
			return NOP_FPU_STACK;
		}
		else if (callFunction && !callLoad)
		{
			return NOP_FPU_STACK;
		}
		else if (callLoad && topVals.find(callLoad->getArgOperand(0)) != topVals.end())
		{
			auto *callFunction = dyn_cast<CallInst>(&analyzedInstr);
			auto it = getFunMd(
					analyzedFunctionsMetadata,
					callFunction->getCalledFunction()
			);
			if (it != analyzedFunctionsMetadata.end())
			{
				auto& fun = it.operator*();
				fun.expectedTop = RETURN_VALUE_PASSED_THROUGH_ST0;
				fun.expectedTopAnalyzed = true;
			}
			return DECREMENT_FPU_STACK;
		}
	}

	return NOP_FPU_STACK;
}

bool X87FpuAnalysis::analyzeBasicBlock(
	std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
	FunctionAnalyzeMetadata& funMd,
	llvm::BasicBlock* bb,
	int& outTop)
{
	std::map<llvm::Value*, int> topVals;
	for (BasicBlock::iterator it = bb->begin(), e = bb->end(); it != e; ++it)
	{
		Instruction* inst = it.operator->();
		if (!analyzeInstruction(analyzedFunctionsMetadata, funMd, inst, outTop))
		{
			return ANALYZE_FAIL;
		}
	}

	return ANALYZE_SUCCESS;
}

bool X87FpuAnalysis::isValidRegisterIndex(int index)
{
	return (X86_REG_ST0 <= index && index <= X86_REG_ST7);
}

bool X87FpuAnalysis::optimizeAnalyzedFpuInstruction(
		std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata)
{
	bool analyzeSucces = true;
	for (auto& funMd : analyzedFunctionsMetadata)
	{
		if (!funMd.analyzeSuccess)
		{
			analyzeSucces = false;
			continue;
		}

		for (auto& i : funMd.pseudoCalls)
		{
			int regBase = uint32_t(X86_REG_ST0);
			auto *callStore = _config->isLlvmX87StorePseudoFunctionCall(i.second);
			auto *callLoad = _config->isLlvmX87LoadPseudoFunctionCall(i.second);

			double bbIn = funMd.x(funMd.indexes[i.second->getParent()][funMd.inIndex], 0);
			int diff = (int)i.first % EMPTY_FPU_STACK; // correction of possible stack over/under-flow
			int top = (int)round(bbIn) + diff; // value of stack at the beginnig of BB + difference at actual instr

			int registerIndex;
			GlobalVariable *reg;
			if (!isValidRegisterIndex(registerIndex = regBase + top%EMPTY_FPU_STACK) || !(reg =_abi->getRegister(registerIndex)))
			{
				analyzeSucces = false;
				continue;
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
