/**
* @file src/llvmir2hll/analysis/use_def_analysis.cpp
* @brief Implementation of UseDefAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/def_use_analysis.h"
#include "retdec/llvmir2hll/analysis/use_def_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builder.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Emits all the live variables info to standard error.
*
* Only for debugging purposes.
*/
void UseDefChains::debugPrint() {
	llvm::errs() << "[UseDefChains] Debug info for function '" << func->getName() << "':\n";
	llvm::errs() << "\n";
	llvm::errs() << "Use-def chains:\n";
	llvm::errs() << "---------------\n";
	for (auto i = ud.begin(), e = ud.end(); i != e; ++i) {
		llvm::errs() << "  ud[" << i->first.first->getName() << ", "
			<< i->first.second << "] (in "
			<< cfg->getNodeForStmt(i->first.second).first->getLabel() << "):\n";
		for (auto j = i->second.begin(), f = i->second.end(); j != f; ++j) {
			llvm::errs() << "    " << (*j) << " (in "
				<< cfg->getNodeForStmt(*j).first->getLabel() << ")\n";
		}
		llvm::errs() << "\n";
	}
}

/**
* @brief Constructs a new analysis.
*
* See create() for the description of the parameters.
*/
UseDefAnalysis::UseDefAnalysis(ShPtr<Module> module):
	module(module) {}

/**
* @brief Destructs the analysis.
*/
UseDefAnalysis::~UseDefAnalysis() {}

/**
* @brief Returns use-def chains for the given function.
*
* @param[in] func Function for which the analysis is computed.
* @param[in] ducs Def-use chains for @a func.
*
* @par Preconditions
*  - @a ducs is non-null
*/
ShPtr<UseDefChains> UseDefAnalysis::getUseDefChains(
		ShPtr<Function> func, ShPtr<DefUseChains> ducs) {
	ShPtr<UseDefChains> udcs(new UseDefChains());
	udcs->func = func;
	udcs->cfg = ducs->cfg;

	computeUseDefChains(udcs, ducs);

	return udcs;
}

/**
* @brief Creates a new analysis.
*
* @param[in] module Module for which the analysis is created.
*/
ShPtr<UseDefAnalysis> UseDefAnalysis::create(ShPtr<Module> module) {
	return ShPtr<UseDefAnalysis>(new UseDefAnalysis(module));
}

/**
* @brief Computes the <tt>UD[x, s]</tt> set for each variable @c x that is
*        used in a statement @c s.
*
* This function modifies @a udcs.
*/
void UseDefAnalysis::computeUseDefChains(ShPtr<UseDefChains> udcs,
		ShPtr<DefUseChains> ducs) {
	// For each def-use chain...
	for (auto i = ducs->du.begin(), e = ducs->du.end(); i != e; ++i) {
		// For each statement in the chain...
		for (auto j = i->second.begin(), f = i->second.end(); j != f; ++j) {
			UseDefChains::VarStmtPair varStmtPair(i->first.second, *j);
			udcs->ud[varStmtPair].insert(i->first.first);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
