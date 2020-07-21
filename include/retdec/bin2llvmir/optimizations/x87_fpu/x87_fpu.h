/**
* @file include/retdec/bin2llvmir/optimizations/x87_fpu/x87_fpu.h
* @brief x87 FPU analysis - replace fpu stack operations with FPU registers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X87_FPU_X87_FPU_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X87_FPU_X87_FPU_H

#include <map>

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"

#define EMPTY_FPU_STACK 8
#define RETURN_VALUE_PASSED_THROUGH_ST0 7
#define DECREMENT_FPU_STACK -1
#define NOP_FPU_STACK 0
#define ANALYZE_FAIL false
#define ANALYZE_SUCCESS true
#define PERFORMANCE_CEIL 1000

namespace retdec {
namespace bin2llvmir {

class FunctionAnalyzeMetadata;

class X87FpuAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		X87FpuAnalysis();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				Abi* a);

	private:
		bool run();
		bool analyzeBasicBlock(
				std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
				FunctionAnalyzeMetadata& funMd,
				llvm::BasicBlock* bb,
				int& outTop);
		bool analyzeInstruction(
				std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
				FunctionAnalyzeMetadata& funMd,
				llvm::Instruction* i,
				int& outTop);

	/**
	 * Replace all FPU pseudo load and store function by load and store with concrete FPU registers.
	 */
	bool optimizeAnalyzedFpuInstruction(
			std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata);
	int expectedTopBasedOnRestOfBlock(
			std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
			llvm::Instruction& analyzedInstr);
	bool checkArchAndCallConvException(llvm::Function* fun);
	bool isValidRegisterIndex(int index);

	private:

		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		llvm::GlobalVariable* top = nullptr;

		std::list<FunctionAnalyzeMetadata>::iterator getFunMd(
				std::list<FunctionAnalyzeMetadata>& analyzedFunctionsMetadata,
				llvm::Function* fun);
};

} // namespace bin2llvmir
} // namespace retdec

#endif
