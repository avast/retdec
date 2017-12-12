/**
* @file src/llvmir2hll/analysis/no_init_var_def_analysis.cpp
* @brief Implementation of NoInitVarDefAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "llvmir2hll/analysis/no_init_var_def_analysis.h"
#include "llvmir2hll/ir/function.h"
#include "llvmir2hll/ir/module.h"
#include "llvmir2hll/ir/var_def_stmt.h"
#include "llvmir2hll/support/debug.h"

namespace llvmir2hll {

NoInitVarDefAnalysis::NoInitVarDefAnalysis() {}

NoInitVarDefAnalysis::~NoInitVarDefAnalysis() {}

/**
* @brief Returns the set of all variable-defining statements without an
*        initializer in the given function.
*
* @param[in] func A function to analyze.
*/
VarDefStmtSet NoInitVarDefAnalysis::getNoInitVarDefStmts(ShPtr<Function> func) {
	noInitVarDefs.clear();
	func->accept(this);

	return noInitVarDefs;
}

void NoInitVarDefAnalysis::visit(ShPtr<VarDefStmt> varDefStmt) {
	if (!varDefStmt->hasInitializer()) {
		noInitVarDefs.insert(varDefStmt);
	}

	// Visit the next statement.
	OrderedAllVisitor::visit(varDefStmt);
}

} // namespace llvmir2hll
