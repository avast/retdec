/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/no_var_def_cfg_traversal.cpp
* @brief Implementation of NoVarDefCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/no_var_def_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;
using retdec::utils::shareSomeItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* @param[in] cfg CFG that should be traversed.
* @param[in] ends Statements at which we should end the traversal.
* @param[in] vars Variables for whose definition/modification we're looking for.
* @param[in] va Analysis of values.
*/
NoVarDefCFGTraversal::NoVarDefCFGTraversal(ShPtr<CFG> cfg, const StmtSet &ends,
		const VarSet &vars, ShPtr<ValueAnalysis> va):
		CFGTraversal(cfg, true), ends(ends), vars(vars), va(va) {}

/**
* @brief Destructs the traverser.
*/
NoVarDefCFGTraversal::~NoVarDefCFGTraversal() {}

/**
* @brief Returns @c true if no variable from @a vars is defined between @a start
*        and statements from @a ends in @a cfg, @c false otherwise.
*
* @param[in] start The search starts from the statement before @a start.
* @param[in] ends Statements at which we should end the traversal.
* @param[in] vars Variables for whose definition/modification we're looking for.
* @param[in] cfg CFG that should be traversed.
* @param[in] va Analysis of values.
*
* During the traversal, it is checked that there are no function calls.
*
* @par Preconditions
*  - @a start, @a cfg, and @a va are non-null
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
bool NoVarDefCFGTraversal::noVarIsDefinedBetweenStmts(ShPtr<Statement> start,
		const StmtSet &ends, const VarSet &vars, ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va) {
	PRECONDITION_NON_NULL(start);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION_NON_NULL(va);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<NoVarDefCFGTraversal> traverser(new NoVarDefCFGTraversal(cfg, ends, vars, va));
	// We mark the start statement as checked so we don't have to check this in
	// visitStmt().
	traverser->checkedStmts.insert(start);
	return traverser->performReverseTraversal(start);
}

bool NoVarDefCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	// Have we reached some destination?
	if (hasItem(ends, stmt)) {
		currRetVal = true;
		return false;
	}

	// Check that there are no function calls.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	if (stmtData->hasCalls()) {
		currRetVal = false;
		return false;
	}

	// Check that no variable from vars is (or may be) modified in the
	// statement.
	if (shareSomeItem(stmtData->getDirWrittenVars(), vars) ||
			shareSomeItem(stmtData->getMayBeWrittenVars(), vars) ||
			shareSomeItem(stmtData->getMustBeWrittenVars(), vars)) {
		currRetVal = false;
		return false;
	}

	return true;
}

bool NoVarDefCFGTraversal::getEndRetVal() const {
	return true;
}

bool NoVarDefCFGTraversal::combineRetVals(bool origRetVal, bool newRetVal) const {
	return origRetVal ? newRetVal : false;
}

} // namespace llvmir2hll
} // namespace retdec
