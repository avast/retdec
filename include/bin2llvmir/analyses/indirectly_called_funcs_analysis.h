/**
* @file include/bin2llvmir/analyses/indirectly_called_funcs_analysis.h
* @brief Indirect calls analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BIN2LLVMIR_ANALYSES_INDIRECTLY_CALLED_FUNCS_ANALYSIS_H
#define BIN2LLVMIR_ANALYSES_INDIRECTLY_CALLED_FUNCS_ANALYSIS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Module.h>

#include "bin2llvmir/utils/defs.h"

namespace bin2llvmir {

/**
* @brief Analysis for finding out which functions can be indirectly called.
*/
class IndirectlyCalledFuncsAnalysis
{
	public:
		static FuncSet getFuncsForIndirectCalls(
				const CallInstSet &call,
				llvm::Module::FunctionListType &funcsToCheck);
		static FuncSet getFuncsForIndirectCall(
				const llvm::CallInst &call,
				const FuncVec &funcsToCheck);
};

} // namespace bin2llvmir

#endif
