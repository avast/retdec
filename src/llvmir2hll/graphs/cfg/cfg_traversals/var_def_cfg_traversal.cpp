/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/var_def_cfg_traversal.cpp
* @brief Implementation of VarDefCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/var_def_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::shareSomeItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* @param[in] cfg CFG that should be traversed.
* @param[in] vars Variables for whose definition/modification we're looking for.
* @param[in] end Statement at which we should end the traversal.
* @param[in] va Analysis of values.
*/
VarDefCFGTraversal::VarDefCFGTraversal(ShPtr<CFG> cfg, const VarSet &vars,
		ShPtr<Statement> end, ShPtr<ValueAnalysis> va):
		CFGTraversal(cfg, false), vars(vars), end(end), va(va) {}

/**
* @brief Destructs the traverser.
*/
VarDefCFGTraversal::~VarDefCFGTraversal() {}

/**
* @brief Returns @c true if a variable from @a vars is defined between @a start
*        and @a end in @a cfg, @c false otherwise.
*
* @param[in] vars Variables for whose definition/modification we're looking for.
* @param[in] start The search starts from the statement before @a start.
* @param[in] end Statement at which we should end the traversal.
* @param[in] cfg CFG that should be traversed.
* @param[in] va Analysis of values.
*
* The search starts from the first statement after @a start.
*
* @par Preconditions
*  - @a start, @a end, and @a va are non-null
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
bool VarDefCFGTraversal::isVarDefBetweenStmts(const VarSet &vars,
		ShPtr<Statement> start, ShPtr<Statement> end, ShPtr<CFG> cfg,
		ShPtr<ValueAnalysis> va) {
	PRECONDITION_NON_NULL(start);
	PRECONDITION_NON_NULL(end);
	PRECONDITION_NON_NULL(va);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<VarDefCFGTraversal> traverser(new VarDefCFGTraversal(cfg, vars, end, va));
	// We mark the start statement as checked so we don't have to check this in
	// visitStmt().
	traverser->checkedStmts.insert(start);
	return traverser->performTraversalFromSuccessors(start);
}

bool VarDefCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	// Check whether we're done.
	if (stmt == end) {
		currRetVal = false;
		return false;
	}

	// Check whether any variable from vars is defined in this statement. Note
	// that it doesn't suffice if the variable may be written -- it either has
	// to be read directly or must be read indirectly.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	if (shareSomeItem(stmtData->getDirWrittenVars(), vars) ||
			shareSomeItem(stmtData->getMustBeWrittenVars(), vars)) {
		currRetVal = true;
		return false;
	}

	return true;
}

bool VarDefCFGTraversal::getEndRetVal() const {
	return false;
}

bool VarDefCFGTraversal::combineRetVals(bool origRetVal, bool newRetVal) const {
	// To return true, it suffices that one variable is defined between the
	// start and end statements.
	return origRetVal || newRetVal;
}

} // namespace llvmir2hll
} // namespace retdec
