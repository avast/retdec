/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversals/auxiliary_variables_cfg_traversal.cpp
* @brief Implementation of AuxiliaryVariablesCFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/auxiliary_variables_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::getKeysFromMap;
using retdec::utils::hasItem;
using retdec::utils::mapHasKey;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* See getAuxiliaryVariables() for more info.
*/
AuxiliaryVariablesCFGTraversal::AuxiliaryVariablesCFGTraversal(ShPtr<Module> module,
		ShPtr<CallInfoObtainer> cio, ShPtr<ValueAnalysis> va, ShPtr<CFG> cfg):
	CFGTraversal(cfg, true), module(module), globalVars(module->getGlobalVars()),
	varsForFuncs(module->getVarsForFuncs()), cg(cio->getCG()), cio(cio), va(va), cfg(cfg),
	func(cfg->getCorrespondingFunction()), notAuxVars(), auxVarToVarMap() {}

/**
* @brief Destructs the traverser.
*/
AuxiliaryVariablesCFGTraversal::~AuxiliaryVariablesCFGTraversal() {}

/**
* @brief Computes auxiliary variables for the function specified by its CFG.
*
* @param[in] module Module which contains the function specified by its CFG.
* @param[in] cio The used call info obtainer.
* @param[in] va The used analysis of values.
* @param[in] cfg CFG that should be traversed.
*
* For the definition of an auxiliary variable, see AuxiliaryVariablesOptimizer.
*
* @par Preconditions
*  - @a module, @a cio, @a va, and @a cfg are non-null
*  - @a cio has been initialized
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
VarSet AuxiliaryVariablesCFGTraversal::getAuxiliaryVariables(ShPtr<Module> module,
		ShPtr<CallInfoObtainer> cio, ShPtr<ValueAnalysis> va, ShPtr<CFG> cfg) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(cio);
	PRECONDITION_NON_NULL(va);
	PRECONDITION_NON_NULL(cfg);
	PRECONDITION(cio->isInitialized(), "it is not initialized");
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<AuxiliaryVariablesCFGTraversal> traverser(new AuxiliaryVariablesCFGTraversal(
		module, cio, va, cfg));
	return traverser->performComputation();
}

/**
* @brief Performs the computation of auxiliary variables.
*/
VarSet AuxiliaryVariablesCFGTraversal::performComputation() {
	// Initialization.
	notAuxVars.clear();
	auxVarToVarMap.clear();

	// Perform the traversal only if the function's body is not empty.
	ShPtr<Statement> startStmt(skipEmptyStmts(func->getBody()));
	if (startStmt) {
		performTraversal(startStmt);
	}

	// The auxiliary variables are precisely the keys in auxVarToVarMap.
	return getKeysFromMap(auxVarToVarMap);
}

/**
* @brief Checks whether the statement assigns something into a variable that
*        can (potentially) be an auxiliary variable.
*
* @return @c true if @a stmt defines a potentially auxiliary variable, @c
*         false otherwise.
*
* If @a stmt defines a potentially auxiliary variable, @c auxVarToVarMap is
* updated. If some variable is found not to be auxiliary, it is added to @c
* notAuxVars.
*/
bool AuxiliaryVariablesCFGTraversal::checkIfStmtIsAuxVarDef(ShPtr<Statement> stmt) {
	// It has to be a statement assigning something into its left-hand side.
	if (!isVarDefOrAssignStmt(stmt) || !getRhs(stmt)) {
		return false;
	}

	// It has to be assigning something into a variable.
	ShPtr<Variable> lhsVar(cast<Variable>(getLhs(stmt)));
	if (!lhsVar) {
		return false;
	}

	// That variable has to satisfy some conditions.
	if (hasItem(notAuxVars, lhsVar) ||
			mapHasKey(auxVarToVarMap, lhsVar) ||
			hasItem(globalVars, lhsVar) ||
			module->hasAssignedDebugName(lhsVar) ||
			lhsVar->isExternal()) {
		return false;
	}

	// The right-hand side has to be a variable.
	ShPtr<Variable> rhsVar(cast<Variable>(getRhs(stmt)));
	if (!rhsVar) {
		notAuxVars.insert(lhsVar);
		return false;
	}

	// That variable has to satisfy some conditions.
	if (hasItem(globalVars, rhsVar) || lhsVar == rhsVar ||
			hasItem(varsForFuncs, rhsVar)) {
		notAuxVars.insert(lhsVar);
		return false;
	}

	// It can potentially be an auxiliary variable.
	auxVarToVarMap[lhsVar] = rhsVar;
	return true;
}

/**
* @brief Checks whether all potentially auxiliary variables are really auxiliary
*        variables.
*
* If some potentially auxiliary variable is found to be not auxiliary, it
* removes it from @c auxVarToVarMap and places it to @c notAuxVars.
*/
void AuxiliaryVariablesCFGTraversal::checkIfPotentialAuxVarsAreAuxVars(
		ShPtr<Statement> stmt) {
	// We have to check that original values corresponding to auxiliary
	// variables are not used in the statement.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	auto i = auxVarToVarMap.begin(), e = auxVarToVarMap.end();
	while (i != e) {
		if (stmtData->isDirAccessed(i->second) ||
				stmtData->mayBeIndirAccessed(i->second) ||
				stmtData->mustBeIndirAccessed(i->second)) {
			// It is not an auxiliary variable.
			notAuxVars.insert(i->first);
			// We need to use i++ to erase the current item while moving to the
			// next item (this cannot be done it two steps, see "c++ iterator
			// invalidation").
			auxVarToVarMap.erase(i++);
		} else {
			++i;
		}
	}
}

bool AuxiliaryVariablesCFGTraversal::visitStmt(ShPtr<Statement> stmt) {
	bool stmtDefinesAuxVar = checkIfStmtIsAuxVarDef(stmt);
	if (!stmtDefinesAuxVar) {
		checkIfPotentialAuxVarsAreAuxVars(stmt);
	}
	return true;
}

bool AuxiliaryVariablesCFGTraversal::getEndRetVal() const {
	// We don't care what the return value is.
	return true;
}

bool AuxiliaryVariablesCFGTraversal::combineRetVals(bool /*origRetVal*/,
		bool /*newRetVal*/) const {
	// We don't care what the return value is.
	return true;
}

} // namespace llvmir2hll
} // namespace retdec
