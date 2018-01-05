/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/optim_func_info_cfg_traversal.cpp
* @brief Implementation of OptimFuncInfoCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/optim_func_info_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;
using retdec::utils::setDifference;
using retdec::utils::setIntersection;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See getOptimFuncInfo() for the description of parameters.
*/
OptimFuncInfoCFGTraversal::OptimFuncInfoCFGTraversal(ShPtr<Module> module,
		ShPtr<OptimCallInfoObtainer> cio, ShPtr<ValueAnalysis> va,
		ShPtr<CFG> cfg):
	CFGTraversal(cfg, true), module(module), globalVars(module->getGlobalVars()),
	cg(cio->getCG()), cio(cio), va(va), cfg(cfg),
	traversedFunc(cfg->getCorrespondingFunction()),
	calledFuncs(cg->getCalledFuncs(cfg->getCorrespondingFunction())),
	funcInfo(new OptimFuncInfo(cfg->getCorrespondingFunction())) {}

/**
* @brief Destructs the traverser.
*/
OptimFuncInfoCFGTraversal::~OptimFuncInfoCFGTraversal() {}

/**
* @brief Computes OptimFuncInfo for the function specified by its CFG.
*
* @param[in] module Module which contains the function specified by its CFG.
* @param[in] cio The used call info obtainer.
* @param[in] va The used analysis of values.
* @param[in] cfg CFG that should be traversed.
* @param[in] va Analysis of values.
*
* @par Preconditions
*  - @a module, @a cio, @a va, and @a cfg are non-null
*  - @a cio has been initialized
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
ShPtr<OptimFuncInfo> OptimFuncInfoCFGTraversal::getOptimFuncInfo(
		ShPtr<Module> module, ShPtr<OptimCallInfoObtainer> cio,
		ShPtr<ValueAnalysis> va, ShPtr<CFG> cfg) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(cio);
	PRECONDITION_NON_NULL(va);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<OptimFuncInfoCFGTraversal> traverser(new OptimFuncInfoCFGTraversal(
		module, cio, va, cfg));
	return traverser->performComputation();
}

/**
* @brief Computes the FuncInfo and returns it.
*/
ShPtr<OptimFuncInfo> OptimFuncInfoCFGTraversal::performComputation() {
	// First, we pre-compute varsAlwaysModifiedBeforeRead. The reason is that
	// their computation differs from the computation of the rest of the sets.
	precomputeAlwaysModifiedVarsBeforeRead();

	// Every function's body is of the following form:
	//
	//    (1) definitions of local variables, including assignments of global
	//        variables into local variables
	//    (2) other statements
	//
	// We store which variables are read/modified in (1). Then, we start the
	// traversal from (2). During the traversal, we check which variables are
	// read/modified and update funcInfo accordingly. The stored information
	// from (1) is used to compute the set of global variables which are read
	// in the function, but not modified.
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
	// Here, even though the global variable orange is modified, its value
	// before calling func() is the same as after calling func(). Indeed, its
	// value is restored before the return statement. Hence, we may put it into
	// funcInfo->varsWithNeverChangedValue.
	// TODO Implement a more robust analysis.
	ShPtr<Statement> currStmt = traversedFunc->getBody();
	while (isVarDefOrAssignStmt(currStmt)) {
		updateFuncInfo(currStmt);

		ShPtr<Expression> lhs(getLhs(currStmt));
		ShPtr<Expression> rhs(getRhs(currStmt));

		// If there is no right-hand side, it is a VarDefStmt with no
		// initializer, which we may skip.
		if (!rhs) {
			currStmt = currStmt->getSuccessor();
			continue;
		}

		// If there are any function calls or dereferences, we have reached
		// (2).
		ShPtr<ValueData> currStmtData(va->getValueData(currStmt));
		if (currStmtData->hasCalls() || currStmtData->hasDerefs()) {
			break;
		}

		// Check whether the statement is of the form localVar = globalVar.
		ShPtr<Variable> localVar(cast<Variable>(lhs));
		ShPtr<Variable> globalVar(cast<Variable>(rhs));
		if (!localVar || !globalVar || hasItem(globalVars, localVar) ||
				!hasItem(globalVars, globalVar)) {
			// It is not of the abovementioned form, so skip it.
			currStmt = currStmt->getSuccessor();
			continue;
		}

		storedGlobalVars[globalVar] = localVar;
		currStmt = currStmt->getSuccessor();
	}

	// Perform the traversal only if we haven't reached the end of the function
	// yet. Since empty statements are not present in a CFG, skip them before
	// the traversal.
	if ((currStmt = skipEmptyStmts(currStmt))) {
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

	// Update funcInfo using the remaining variables in storedGlobalVars.
	for (const auto &p : storedGlobalVars) {
		funcInfo->varsWithNeverChangedValue.insert(p.first);
	}

	// Update funcInfo->never{Read,Modified}Vars by global variables which are
	// untouched in this function.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		ShPtr<Variable> var((*i)->getVar());
		if (!hasItem(funcInfo->mayBeReadVars, var) &&
				!hasItem(funcInfo->mayBeModifiedVars, var)) {
			funcInfo->neverReadVars.insert(var);
			funcInfo->neverModifiedVars.insert(var);
		}
	}

	// If the cfg contains only a single non-{entry,exit} node, every
	// mayBe{Read,Modifed} variable can be turned into a always{Read,Modified}
	// variable.
	if (cfg->getNumberOfNodes() == 3) {
		addToSet(funcInfo->mayBeReadVars, funcInfo->alwaysReadVars);
		addToSet(funcInfo->mayBeModifiedVars, funcInfo->alwaysModifiedVars);
	}

	// Add all variables which are never read and never modified to
	// varsWithNeverChangedValue.
	VarSet neverReadAndModifedVars(setIntersection(funcInfo->neverReadVars,
		funcInfo->neverModifiedVars));
	addToSet(neverReadAndModifedVars, funcInfo->varsWithNeverChangedValue);

	// Add all global variables are not read in this function into
	// varsAlwaysModifiedBeforeRead.
	addToSet(setDifference(globalVars, funcInfo->mayBeReadVars),
		funcInfo->varsAlwaysModifiedBeforeRead);

	return funcInfo;
}

/**
* @brief Precomputes @c funcInfo->isAlwaysModifiedBeforeRead for @c traversedFunc.
*/
void OptimFuncInfoCFGTraversal::precomputeAlwaysModifiedVarsBeforeRead() {
	// Initialization.
	funcInfo->varsAlwaysModifiedBeforeRead.clear();
	// Global variables which are read during the computation.
	VarSet readVars;

	// Currently, we only traverse the function's body up to the first compound
	// statement. Moreover, we only consider global variables as the computed
	// piece of information is useless for local variables.
	// TODO Use a CFG traversal for this to improve the analysis.
	ShPtr<Statement> stmt(traversedFunc->getBody());
	while (stmt) {
		if (stmt->isCompound()) {
			// As we are not using a CFG traversal, this is the end of the
			// computation.
			break;
		}

		ShPtr<ValueData> stmtData(va->getValueData(stmt));

		// Handle directly read variables.
		addToSet(stmtData->getDirReadVars(), readVars);

		// Handle function calls (indirectly accessed variables).
		for (auto i = stmtData->call_begin(), e = stmtData->call_end(); i != e; ++i) {
			ShPtr<CallInfo> callInfo(cio->computeCallInfo(*i, traversedFunc));
			for (const auto &var : globalVars) {
				if (callInfo->mayBeRead(var)) {
					readVars.insert(var);
				}
			}
		}

		// Handle directly written variables.
		for (auto i = stmtData->dir_written_begin(), e = stmtData->dir_written_end();
				i != e; ++i) {
			if (hasItem(globalVars, *i) && !hasItem(readVars, *i)) {
				// This global variable is modified before read.
				funcInfo->varsAlwaysModifiedBeforeRead.insert(*i);
			}
		}

		// TODO What about indirectly accessed variables?

		stmt = stmt->getSuccessor();
	}
}

/**
* @brief Updates @c funcInfo by the information obtained from the given
*        statement.
*/
void OptimFuncInfoCFGTraversal::updateFuncInfo(ShPtr<Statement> stmt) {
	// Update the set of variables that are read and modified in the function.
	// Currently, we put also must-be-{read,modified} variables into
	// funcInfo->mayBe{Read,Modified}Vars. The reason is that we do not perform
	// any kind of analysis which variables are truly always accessed. For
	// example, if there is an if statement in the function, its body may never
	// be entered etc.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	addToSet(stmtData->getDirReadVars(), funcInfo->mayBeReadVars);
	addToSet(stmtData->getMayBeReadVars(), funcInfo->mayBeReadVars);
	addToSet(stmtData->getMustBeReadVars(), funcInfo->mayBeReadVars);
	addToSet(stmtData->getDirWrittenVars(), funcInfo->mayBeModifiedVars);
	addToSet(stmtData->getMayBeWrittenVars(), funcInfo->mayBeModifiedVars);
	addToSet(stmtData->getMustBeWrittenVars(), funcInfo->mayBeModifiedVars);

	// Update storedGlobalVars. If the statement writes into a variable in
	// storedGlobalVars, we have to remove it from storedGlobalVars. Indeed, we
	// require that no local variable storing a global variable is written-into,
	// just read.
	const VarSet &dirWrittenVars(stmtData->getDirWrittenVars());
	const VarSet &mayBeWrittenVars(stmtData->getMayBeWrittenVars());
	const VarSet &mustBeWrittenVars(stmtData->getMustBeWrittenVars());
	for (auto i = storedGlobalVars.begin(), e = storedGlobalVars.end();
			i != e; ++i) {
		if (hasItem(dirWrittenVars, i->second) ||
				hasItem(mayBeWrittenVars, i->second) ||
				hasItem(mustBeWrittenVars, i->second)) {
			storedGlobalVars.erase(i);
			break;
		}
	}

	// Handle function calls.
	// TODO What if a call modifies a local variable from storedGlobalVars?
	for (const auto &call : stmtData->getCalls()) {
		ShPtr<OptimCallInfo> callInfo(cast<OptimCallInfo>(
			cio->computeCallInfo(call, traversedFunc)
		));

		addToSet(callInfo->mayBeReadVars, funcInfo->mayBeReadVars);
		addToSet(callInfo->mayBeModifiedVars, funcInfo->mayBeModifiedVars);
	}
}

/**
* @brief Checks the selected predecessor of the exit node of @c cfg.
*
* @return @c true if the next exit node's predecessor should be checked, @c
*         false otherwise. If @c false is returned, it means that no variables
*         from storedGlobalVars can be marked as 'never modified'.
*
* This function checks that every variable from @c storedGlobalVars is
* retrieved its original value before the node exits.
*/
bool OptimFuncInfoCFGTraversal::checkExitNodesPredecessor(ShPtr<CFG::Node> node) {
	if (node == cfg->getEntryNode()) {
		// We have reached the entry node.
		return false;
	}

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
	// its original value, then this variable cannot be marked as 'never
	// modified'.

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
		ShPtr<ValueData> rhsData(va->getValueData(rhs));
		if (!lhs || rhsData->hasCalls() || rhsData->hasDerefs()) {
			break;
		}

		// Check whether the statement is of the form globalVar = localVar,
		// where globalVar is a variable from toCheck and localVar its
		// corresponding local variable.
		auto lhsFoundIter = toCheck.find(lhs);
		if (lhsFoundIter != toCheck.end() && lhsFoundIter->second == rhs) {
			toCheck.erase(lhsFoundIter);
		}

		// Move to the "next" (i.e. previous) statement (if any).
		if (++currStmtRIter != node->stmt_rend()) {
			currStmt = *currStmtRIter;
		}
	}

	// If toCheck contains some variables at this moment, they cannot be
	// marked as 'never modified'.
	for (const auto &p : toCheck) {
		storedGlobalVars.erase(p.first);
	}

	// The checking should continue only if there are still some variables that
	// can possibly be marked as 'never modified'.
	return !storedGlobalVars.empty();
}

bool OptimFuncInfoCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	updateFuncInfo(stmt);
	return true;
}

bool OptimFuncInfoCFGTraversal::getEndRetVal() const {
	return true;
}

bool OptimFuncInfoCFGTraversal::combineRetVals(bool /*origRetVal*/,
		bool /*newRetVal*/) const {
	// We don't care what the return value is.
	return true;
}

} // namespace llvmir2hll
} // namespace retdec
