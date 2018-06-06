/**
* @file include/retdec/bin2llvmir/analyses/indirectly_called_funcs_analysis.h
* @brief Indirect calls analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_INDIRECTLY_CALLED_FUNCS_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_INDIRECTLY_CALLED_FUNCS_ANALYSIS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace retdec {
namespace bin2llvmir {

/**
* @brief Analysis for finding out which functions can be indirectly called.
*/
class IndirectlyCalledFuncsAnalysis
{
	public:
		static std::set<llvm::Function*> getFuncsForIndirectCalls(
				const std::set<llvm::CallInst*> &call,
				llvm::Module::FunctionListType &funcsToCheck);
		static std::set<llvm::Function*> getFuncsForIndirectCall(
				const llvm::CallInst &call,
				const std::vector<llvm::Function*> &funcsToCheck);
};

} // namespace bin2llvmir
} // namespace retdec

#endif
