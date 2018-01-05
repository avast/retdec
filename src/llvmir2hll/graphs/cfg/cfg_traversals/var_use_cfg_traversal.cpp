/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/var_use_cfg_traversal.cpp
* @brief Implementation of VarUseCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/var_use_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See the description of isDefinedPriorToEveryAccess() for information on the
* parameters.
*/
VarUseCFGTraversal::VarUseCFGTraversal(ShPtr<Variable> var,
		ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va):
	CFGTraversal(cfg, true), var(var), va(va) {}

/**
* @brief Destructs the traverser.
*/
VarUseCFGTraversal::~VarUseCFGTraversal() {}

/**
* @brief Returns @c true if the given variable @a var is defined/modified prior
*        to every read access to it in @a cfg.
*
* @param[in] var Variable whose definition/modification is looked for.
* @param[in] cfg CFG that should be traversed.
* @param[in] va Analysis of values.
*
* @par Preconditions
*  - @a var, @a cfg, and @a va are non-null
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
bool VarUseCFGTraversal::isDefinedPriorToEveryAccess(ShPtr<Variable> var,
		ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION_NON_NULL(va);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<VarUseCFGTraversal> traverser(new VarUseCFGTraversal(var, cfg, va));

	// Obtain the first statement of the function. We have to skip the entry
	// node because there are no statements corresponding to the VarDefStmts
	// for function parameters.
	ShPtr<CFG::Node> funcBodyNode((*cfg->getEntryNode()->succ_begin())->getDst());
	ShPtr<Statement> firstStmt(*funcBodyNode->stmt_begin());

	return traverser->performTraversal(firstStmt);
}

bool VarUseCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	ShPtr<ValueData> stmtData(va->getValueData(stmt));

	/* TODO Include the following restriction?
	// There should not be any function calls.
	if (stmtData->hasCalls()) {
		return false;
	}
	*/

	// Check whether the variable is read prior modifying; if so, we are done.
	if (stmtData->isDirRead(var) || stmtData->mayBeIndirRead(var) ||
			stmtData->mustBeIndirRead(var)) {
		currRetVal = false;
		return false;
	}

	// Check whether we are modifying the variable. Here, it doesn't suffice
	// that the variable may be read -- it either has to be read directly or
	// must be read indirectly.
	if (stmtData->isDirWritten(var) || stmtData->mustBeIndirWritten(var)) {
		currRetVal = true;
		return false;
	}

	return true;
}

bool VarUseCFGTraversal::getEndRetVal() const {
	return true;
}

bool VarUseCFGTraversal::combineRetVals(bool origRetVal, bool newRetVal) const {
	return origRetVal ? newRetVal : false;
}

} // namespace llvmir2hll
} // namespace retdec
