/**
* @file include/retdec/bin2llvmir/analyses/reachable_funcs_analysis.h
* @brief Reachable functions analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_REACHABLE_FUNCS_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_REACHABLE_FUNCS_ANALYSIS_H

#include <string>

#include <llvm/ADT/SCCIterator.h>
#include <llvm/Analysis/CallGraph.h>

namespace retdec {
namespace bin2llvmir {

/**
* @brief Analysis for finding out which defined functions are directly and
*        indirectly reachable from some function.
*/
class ReachableFuncsAnalysis {
public:
	ReachableFuncsAnalysis();
	~ReachableFuncsAnalysis();

	std::string getName() const { return "ReachableFuncsAnalysis"; }

	static std::set<llvm::Function*> getReachableDefinedFuncsFor(llvm::Function &func,
		llvm::Module &module, llvm::CallGraph &callGraph);
	static std::set<llvm::Function*> getGloballyReachableFuncsFor(llvm::Module &module);

private:
	std::set<llvm::Function*> getDirectlyReachableDefinedFuncsFor(
		const std::set<llvm::Function*> &funcs, llvm::CallGraph &callGraph) const;
	std::set<llvm::Function*> getDirectlyReachableDefinedFuncsFor(
		llvm::CallGraphNode &reachableFrom) const;
	std::set<llvm::Function*> getIndirectlyReachableDefinedFuncsFor(
		const std::set<llvm::Function*> &funcs, llvm::Module &module) const;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
