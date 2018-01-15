/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/modified_before_read_cfg_traversal.cpp
* @brief Implementation of ModifiedBeforeReadCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/modified_before_read_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See the description of isModifiedBeforeEveryRead() for information on the
* parameters.
*/
ModifiedBeforeReadCFGTraversal::ModifiedBeforeReadCFGTraversal(ShPtr<Variable> var,
		ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
	// The false value passed to CFGTraversal below means that the variable was
	// not modified when initializing the traversal.
	CFGTraversal(cfg, false), var(var), va(va), cio(cio),
	wasModifiedBeforeEveryRead(true) {}

/**
* @brief Destructs the traverser.
*/
ModifiedBeforeReadCFGTraversal::~ModifiedBeforeReadCFGTraversal() {}

/**
* @brief Returns @c true if the given variable @a var is modified prior to
*        every read access to it in @a cfg, starting from @a startStmt.
*
* @param[in] var Variable whose modification is looked for.
* @param[in] startStmt Statement from which the traversal should start.
* @param[in] cfg CFG that should be traversed.
* @param[in] va Analysis of values.
* @param[in] cio Obtainer of information about function calls.
*
* @par Preconditions
*  - @a var, @a stmt, @a cfg, @a va are non-null
*  - @a va is in a valid state
*  - @a cio is initialized
*
* This function leaves @a va in a valid state.
*
* If the variable is not modified at all, this function also returns @c false.
*/
bool ModifiedBeforeReadCFGTraversal::isModifiedBeforeEveryRead(ShPtr<Variable> var,
		ShPtr<Statement> startStmt, ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(startStmt);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION_NON_NULL(va);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");
	PRECONDITION(cio->isInitialized(), "it is not initialized");

	ShPtr<ModifiedBeforeReadCFGTraversal> traverser(
		new ModifiedBeforeReadCFGTraversal(var, cfg, va, cio));
	bool wasModified(traverser->performTraversal(startStmt));
	return wasModified && traverser->wasModifiedBeforeEveryRead;
}

bool ModifiedBeforeReadCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	ShPtr<ValueData> stmtData(va->getValueData(stmt));

	// If the variable is read, we are done.
	if (stmtData->isDirRead(var) || stmtData->mayBeIndirRead(var)) {
		wasModifiedBeforeEveryRead = false;
		stopTraversal = true;
		return false;
	}

	if (stmtData->hasCalls()) {
		bool isModifiedInAllCalls(true);
		for (auto i = stmtData->call_begin(), e = stmtData->call_end();
				i != e; ++i) {
			ShPtr<CallInfo> callInfo(cio->getCallInfo(*i,
				cfg->getCorrespondingFunction()));

			// If the variable may be read before modifying in a
			// call, we are done.
			if (!callInfo->isAlwaysModifiedBeforeRead(var)) {
				wasModifiedBeforeEveryRead = false;
				stopTraversal = true;
				return false;
			}

			if (!callInfo->isAlwaysModified(var)) {
				isModifiedInAllCalls = false;
			}
		}

		// If the variable is always modified in all the calls, we are done.
		if (isModifiedInAllCalls) {
			wasModifiedBeforeEveryRead = true;
			currRetVal = true;
			return false;
		}
	}

	// If the variable is modified, we are done.
	if (stmtData->isDirWritten(var) || stmtData->mustBeIndirWritten(var)) {
		wasModifiedBeforeEveryRead = true;
		currRetVal = true;
		return false;
	}

	return true;
}

bool ModifiedBeforeReadCFGTraversal::getEndRetVal() const {
	// By default, we assume that the variable was not modified.
	return false;
}

bool ModifiedBeforeReadCFGTraversal::combineRetVals(bool origRetVal,
		bool newRetVal) const {
	// If the variable was modified (origRetVal == true), then return the old
	// value (true); otherwise, return the new value.
	return origRetVal ? true : newRetVal;
}

} // namespace llvmir2hll
} // namespace retdec
