/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/unneeded_global_vars_cfg_traversal.cpp
* @brief Implementation of UnneededGlobalVarsCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/unneeded_global_vars_cfg_traversal.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::getKeysFromMap;
using retdec::utils::hasItem;
using retdec::utils::mapHasKey;
using retdec::utils::setIntersection;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See the description of getUnneededGlobalVars() for more information on
* parameters.
*/
UnneededGlobalVarsCFGTraversal::UnneededGlobalVarsCFGTraversal(
		ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio, ShPtr<CFG> cfg):
	CFGTraversal(cfg, false), module(module), globalVars(module->getGlobalVars()),
	va(va), cio(cio), cfg(cfg), traversedFunc(cfg->getCorrespondingFunction()) {}

/**
* @brief Destructs the traverser.
*/
UnneededGlobalVarsCFGTraversal::~UnneededGlobalVarsCFGTraversal() {}

/**
* @brief Returns all the ``unneeded'' global variables from a function specified
*        by its CFG.
*
* @param[in] module Module in which the function specified by its CFG is.
* @param[in] va Analysis of values.
* @param[in] cio The used call info obtainer.
* @param[in] cfg CFG that should be traversed.
*
* For more information, mainly for the definition of a ``needed'' global
* variable, see GlobalToLocalOptimizer::performConvertUnneededGlobalVars().
*
* @par Preconditions
*  - @a module, @a va, @a cio, and @a cfg are non-null
*  - @a cio is initialized
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
ShPtr<UnneededGlobalVarsCFGTraversal::UnneededGlobalVars> UnneededGlobalVarsCFGTraversal::
		getUnneededGlobalVars(ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio, ShPtr<CFG> cfg) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(va);
	PRECONDITION_NON_NULL(cio);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION(cio->isInitialized(), "it is not initialized");
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<UnneededGlobalVarsCFGTraversal> traverser(new UnneededGlobalVarsCFGTraversal(
		module, va, cio, cfg));
	return traverser->performUnneededGlobalVarsComputation();
}

/**
* @brief Performs the computation of unneeded global variables.
*
* @return The computed set of unneeded global variables.
*/
ShPtr<UnneededGlobalVarsCFGTraversal::UnneededGlobalVars> UnneededGlobalVarsCFGTraversal::
		performUnneededGlobalVarsComputation() {
	storedGlobalVars.clear();
	unneededStmts.clear();

	// The code below is based on CFG/OptimFuncInfoCFGTraversal.

	// Every function's body is of the following form:
	//
	//    (1) definitions of local variables, including assignments of global
	//        variables into local variables
	//    (2) other statements
	//
	// We store which variables are read/modified in (1). Then, we start the
	// traversal from (2). During the traversal, we check which variables are
	// read/modified. The stored information from (1) is used to compute the
	// set of unneeded global variables.
	//
	// To give a specific example, consider the following code:
	//
	// def func(mango):
	//    global orange
	//    global plum
	//    lychee = orange
	//    achira = plum
	//    orange = mango
	//    plum = rand()
	//    result = plum * apple + orange
	//    orange = lychee
	//    plum = achira
	//    return result
	//
	// Here, the variable orange is not needed to be global. Indeed, its value
	// is first stored into a temporary variable lychee, and restored at the
	// end of the function. The same holds for the global variable plum.
	// Therefore, in this case, the set of unneeded global variables is
	// {orange, plum}.
	ShPtr<Statement> currStmt = traversedFunc->getBody();
	while (isVarDefOrAssignStmt(currStmt)) {
		updateUnneededGlobalVarsInfo(currStmt);

		ShPtr<Expression> lhs(getLhs(currStmt));
		ShPtr<Expression> rhs(getRhs(currStmt));

		// If there is no right-hand side, it is a VarDefStmt with no
		// initializer, which we may skip.
		if (!rhs) {
			currStmt = currStmt->getSuccessor();
			continue;
		}

		// Check whether the statement is of the form lhsVar = rhsVar, possibly
		// with casts on the right-hand side.
		ShPtr<Variable> lhsVar(cast<Variable>(lhs));
		ShPtr<Variable> rhsVar(cast<Variable>(skipCasts(rhs)));
		if (!lhsVar || !rhsVar) {
			currStmt = currStmt->getSuccessor();
			continue;
		}

		// If the current statement modifies a global variable that was on the
		// right-hand side of one of the previous assignments, we have reached
		// phase (2).
		auto i = storedGlobalVars.find(lhsVar);
		if (i != storedGlobalVars.end() && i->second == rhsVar) {
			break;
		}

		// The left-hand side has to be a local variable and the right-hand
		// side has to be a global variable.
		if (hasItem(globalVars, lhsVar) || !hasItem(globalVars, rhsVar)) {
			currStmt = currStmt->getSuccessor();
			continue;
		}

		// Never consider external global variables as unneeded because we may
		// not have all the available information for them (for example, in
		// selective decompilation, an external variable may be changed outside
		// of the decompiled code).
		if (rhsVar->isExternal()) {
			currStmt = currStmt->getSuccessor();
			continue;
		}

		// Check that there does not already exist a mapping for the global
		// variable (in such cases, we use the original one).
		if (mapHasKey(storedGlobalVars, rhsVar)) {
			currStmt = currStmt->getSuccessor();
			continue;
		}

		storedGlobalVars[rhsVar] = lhsVar;
		unneededStmts.insert(currStmt);
		currStmt = currStmt->getSuccessor();
	}

	// Perform the traversal only if we haven't reached the end of the function
	// yet.
	if (currStmt) {
		// Since empty statements are not present in a CFG, skip them before
		// the traversal.
		currStmt = skipEmptyStmts(currStmt);

		performTraversal(currStmt);
	}

	// We use the exit node of the CFG to check that every variable from
	// storedGlobalVars is retrieved its original value before every return.
	ShPtr<CFG::Node> exitNode(cfg->getExitNode());
	// For every predecessor of the exit node...
	for (auto i = exitNode->pred_begin(), e = exitNode->pred_end(); i != e; ++i) {
		bool checkingShouldContinue = checkExitNodesPredecessor((*i)->getSrc());
		if (!checkingShouldContinue) {
			break;
		}
	}

	// Purge unneededStmts by keeping only the statements which access unneeded
	// global variables. This has to be done because we have only added
	// statements to unneededStmts during the computation. Indeed, until now,
	// we have never removed anything from this set, so there may be statements
	// accessing variables which we thought would be unneeded, but are actually
	// needed.
	VarSet unneededGlobalVars(getKeysFromMap(storedGlobalVars));
	// For every unneeded statement...
	auto i = unneededStmts.begin();
	while (i != unneededStmts.end()) {
		const VarSet &usedVars(va->getValueData(*i)->getDirAccessedVars());
		if (setIntersection(usedVars, unneededGlobalVars).empty()) {
			unneededStmts.erase(*i++);
		} else {
			++i;
		}
	}

	return ShPtr<UnneededGlobalVars>(new UnneededGlobalVars(traversedFunc,
		unneededGlobalVars, unneededStmts));
}

/**
* @brief Updates @c storedGlobalVars and other related attributes by the
*        information obtained from the given statement.
*/
void UnneededGlobalVarsCFGTraversal::updateUnneededGlobalVarsInfo(ShPtr<Statement> stmt) {
	// Update storedGlobalVars by indirectly accessed
	// variables.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	// For every function call...
	for (const auto &call : stmtData->getCalls()) {
		ShPtr<CallInfo> callInfo(cio->getCallInfo(call, traversedFunc));
		for (const auto var : globalVars) {
			if (!callInfo->valueIsNeverChanged(var)) {
				storedGlobalVars.erase(var);
			}
		}
	}

	// Update storedGlobalVars by checking assignments.
	if (ShPtr<AssignStmt> assignStmt = cast<AssignStmt>(stmt)) {
		if (ShPtr<Variable> lhsVar = cast<Variable>(assignStmt->getLhs())) {
			// Is lhsVar a variable holding a global variable?
			for (auto i = storedGlobalVars.begin(), e = storedGlobalVars.end();
					i != e; ++i) {
				if (i->second == lhsVar) {
					// It is, so this global variable is probably not a
					// variable whose value is never changed in this function.
					storedGlobalVars.erase(i);
					break;
				}
			}
		}
	}

	// TODO What if a function call modifies a local variable from
	//      storedGlobalVars?
}

/**
* @brief Checks the selected predecessor of the exit node of @c cfg.
*
* @return @c true if the next exit node's predecessor should be checked, @c
*         false otherwise. If @c false is returned, it means that no variables
*         from storedGlobalVars can be marked as 'with never changed value'.
*
* This function checks that every variable from @c storedGlobalVars is
* retrieved its original value before the node exits.
*/
bool UnneededGlobalVarsCFGTraversal::checkExitNodesPredecessor(ShPtr<CFG::Node> node) {
	auto currStmtRIter = node->stmt_rbegin();
	ASSERT_MSG(currStmtRIter != node->stmt_rend(), "encountered an empty node");
	ShPtr<Statement> currStmt = *currStmtRIter;

	// Before every return, there should be a sequence
	//
	//    globalVar1 = localVar1
	//    globalVar2 = localVar1
	//    ...
	//
	// where globalVarX is a key in storedGlobalVars and localVarsX is the
	// corresponding value.
	//
	// If some global variable before a return statement is not retrieved
	// its original value, then this variable cannot be marked as unneeded.

	// Check whether there is a statement to be skipped. We currently skip
	// just return statements.
	// TODO Skip also other statements?
	if (isa<ReturnStmt>(currStmt) && ++currStmtRIter != node->stmt_rend()) {
		currStmt = *currStmtRIter;
	}

	// Check all variables from storedGlobalVars.
	VarToVarMap toCheck(storedGlobalVars);
	while (currStmtRIter != node->stmt_rend() && isa<AssignStmt>(currStmt)) {
		ShPtr<AssignStmt> assignStmt = cast<AssignStmt>(currStmt);
		ShPtr<Variable> lhs(cast<Variable>(assignStmt->getLhs()));
		ShPtr<Expression> rhs(assignStmt->getRhs());

		// If the left-hand side is not a variable or there are some
		// function calls or dereferences, stop the check.
		ShPtr<ValueData> currStmtData(va->getValueData(currStmt));
		if (!lhs || currStmtData->hasCalls() || currStmtData->hasDerefs()) {
			break;
		}

		// Check whether the statement is of the form globalVar = localVar,
		// where globalVar is a variable from toCheck and localVar its
		// corresponding local variable.
		auto lhsFoundIter = toCheck.find(lhs);
		if (lhsFoundIter != toCheck.end() && lhsFoundIter->second == rhs) {
			unneededStmts.insert(currStmt);
			toCheck.erase(lhsFoundIter);
		}

		// Move to the "next" (i.e. previous) statement (if any).
		if (++currStmtRIter != node->stmt_rend()) {
			currStmt = *currStmtRIter;
		}
	}

	// If toCheck contains some variables at this moment, they cannot be
	// marked as 'with never changed value'.
	for (const auto &p : toCheck) {
		storedGlobalVars.erase(p.first);
	}

	// The checking should continue only if there are still some variables that
	// can possibly be marked as 'with never changed value'.
	return !storedGlobalVars.empty();
}

bool UnneededGlobalVarsCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	updateUnneededGlobalVarsInfo(stmt);
	return true;
}

bool UnneededGlobalVarsCFGTraversal::getEndRetVal() const {
	return true;
}

bool UnneededGlobalVarsCFGTraversal::combineRetVals(bool /*origRetVal*/,
		bool /*newRetVal*/) const {
	// We don't care what the return value is.
	return true;
}

} // namespace llvmir2hll
} // namespace retdec
