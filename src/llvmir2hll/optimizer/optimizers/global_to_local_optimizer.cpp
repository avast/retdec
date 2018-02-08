/**
* @file src/llvmir2hll/optimizer/optimizers/global_to_local_optimizer.cpp
* @brief Implementation of GlobalToLocalOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/unneeded_global_vars_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/var_use_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/global_to_local_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/variable_replacer.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va The used analysis of values.
* @param[in] cio Obtainer of information about function calls.
*
* @par Preconditions
*  - @a module, @a va, and @a cio are non-null
*/
GlobalToLocalOptimizer::GlobalToLocalOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
	Optimizer(module), cg(CGBuilder::getCG(module)), va(va), cio(cio),
	vuv(), usefulGlobalVars(), uselessGlobalVars(),
	funcUsedGlobalVarsMap() {
		PRECONDITION_NON_NULL(module);
		PRECONDITION_NON_NULL(va);
		PRECONDITION_NON_NULL(cio);
	}

/**
* @brief Destructs the optimizer.
*/
GlobalToLocalOptimizer::~GlobalToLocalOptimizer() {}

void GlobalToLocalOptimizer::doOptimization() {
	// Initialization.
	if (!va->isInValidState()) {
		va->clearCache();
	}

	//
	// This optimization is divided into several sub-optimizations. They are
	// denoted by upper-case roman numbers. We perform them one by one,
	// initializing all the required information before every sub-optimization.
	//

	// TODO How to optimize the code below so cio->init() and va->init()
	//      suffice to be called just once?
	//      Now, we need to recompute them before some sub-optimizations
	//      because erasure of global variables doesn't change
	//      funcUsedGlobalVarsMap. However, we cannot simply update
	//      funcUsedGlobalVarsMap because it is not that simple (due to calls
	//      in functions and indirect calls).

	// (I)
	cio->init(cg, va);
	computeGlobalVars();
	computeUsedGlobalVars();
	computeUsefulAndUselessGlobalVars();
	convertUselessGlobalVars();

	// (II)
	computeGlobalVars();
	computeUsedGlobalVars();
	convertUnneededGlobalVars();

	// (III)
	va->clearCache();
	cio->init(cg, va);
	computeGlobalVars();
	computeUsedGlobalVars();
	convertOtherGlobalVars();

	// (IV)
	computeGlobalVars();
	computeUsedGlobalVars();
	removeUnusedGlobalVars();

	// Currently, we do not update the used analysis of values (va) during this
	// optimization, so here, at the end of the optimization, we have to put it
	// into an invalid state.
	// TODO Regularly update the cache of va so we do not have to invalidate it.
	va->invalidateState();
}

/**
* @brief Removes global variables which are not used in any function.
*
* Such variables may be just removed, without any need to convert them to local
* variables.
*/
void GlobalToLocalOptimizer::removeUnusedGlobalVars() {
	for (const auto &var : globalVars) {
		if (globalVarMayBeRemovedAsUnused(var)) {
			module->removeGlobalVar(var);
		}
	}
}

/**
* @brief Converts so-called ``useless'' global variables into local variables.
*
* See the description of computeUsefulAndUselessGlobalVars() for the definition
* of a ``useless'' global variable.
*
* @par Preconditions
*  - @c usefulGlobalVars has been computed
*/
void GlobalToLocalOptimizer::convertUselessGlobalVars() {
	// For each useless global variable...
	for (const auto &var : uselessGlobalVars) {
		ShPtr<Expression> init(module->getInitForGlobalVar(var));

		// For each function...
		for (auto j = module->func_definition_begin(),
				f = module->func_definition_end(); j != f; ++j) {
			if (hasItem(funcUsedGlobalVarsMap[*j], var)) {
				convertGlobalVarToLocalVarInFunc(var, *j, init);
			}
		}

		module->removeGlobalVar(var);
	}
}

/**
* @brief Converts ``unneeded'' global variables into local variables, for every
*        function.
*
* A global variable @c v is ``needed'' in a function @c f if (1) @c f uses @c v
* and (2) @c v has to be a global variable, i.e. it cannot be converted into a
* local variable. @c v is ``unneeded'' in @c f if (1) holds but (2) doesn't
* hold.
*
* For example, consider the following program:
* @code
* orange = 0
* plum = 0
*
* def my_sum1(mango):
*    global orange
*    global plum
*    lychee = orange
*    achira = plum
*    orange = mango
*    plum = rand()
*    tangerine = rand()
*    result = plum + tangerine + orange
*    orange = lychee
*    plum = achira
*    return result
* @endcode
*
* First, global variables @c orange and @c plum are stored into two local
* variables, @c lychee and @c achira. Then, a computation is performed, possibly
* using the global variables to store temporary values. Before the return,
* their original value is restored.
*
* In this case, these two variables may be converted into local variables.
* Afterwards, the subsequent CopyPropagation optimization should be able to
* clear the code.
*/
void GlobalToLocalOptimizer::convertUnneededGlobalVars() {
	// For each function...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		convertUnneededGlobalVarsForFunc(*i);
	}
}

/**
* @brief Converts ``unneeded'' global variables in @a func into local variables.
*
* See the description of convertUnneededGlobalVars() for more info.
*
* @par Preconditions
*  - @a func is non-null
*  - @c funcUsedGlobalVarsMap has been computed
*/
void GlobalToLocalOptimizer::convertUnneededGlobalVarsForFunc(
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(func);

	// Compute all unneeded global variables in the function.
	ShPtr<UnneededGlobalVarsCFGTraversal::UnneededGlobalVars> unneededGlobalVars(
		UnneededGlobalVarsCFGTraversal::getUnneededGlobalVars(module, va, cio,
		cio->getCFGForFunc(func)));

	// Removed unneeded statements.
	for (const auto &stmt : unneededGlobalVars->stmts) {
		Statement::removeStatementButKeepDebugComment(stmt);
	}

	// Convert all the unneeded global variables into local variables.
	for (const auto &var : unneededGlobalVars->vars) {
		convertGlobalVarToLocalVarInFunc(var, func);
	}
}

/**
* @brief Converts global variables to local variable by other checks, not
*        included in removeUnusedGlobalVars() and convertUselessGlobalVars().
*
* @par Preconditions
*  - @c funcUsedGlobalVarsMap have been computed
*/
void GlobalToLocalOptimizer::convertOtherGlobalVars() {
	// For each function...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		// For each global variable used in the function...
		for (const auto &var : funcUsedGlobalVarsMap[*i]) {
			if (globalVarMayBeConverted(var, *i)) {
				ShPtr<Expression> init(module->getInitForGlobalVar(var));
				convertGlobalVarToLocalVarInFunc(var, *i, init);
			}
		}
	}
}

/**
* @brief Computes @c globalVars.
*
* This function should be called before every sub-optimization.
*/
void GlobalToLocalOptimizer::computeGlobalVars() {
	globalVars = module->getGlobalVars();
}

/**
* @brief Computes @c globalVarsUsedInGlobalVarDef.
*
* This function should be called before every sub-optimization, after
* computeGlobalVars().
*
* @par Preconditions
*  - @c globalVars has been computed
*/
void GlobalToLocalOptimizer::computeGlobalVarsUsedInGlobalVarDef() {
	globalVarsUsedInGlobalVarDef.clear();

	// For every global variable in the module...
	for (auto i = module->global_var_begin(),
			e = module->global_var_end(); i != e; ++i) {
		// Skip global variables without an initializer because they have no
		// variables on their right-hand side.
		if (!(*i)->hasInitializer()) {
			continue;
		}

		// For every variable that is directly read in the definition...
		ShPtr<ValueData> initData(va->getValueData((*i)->getInitializer()));
		for (auto j = initData->dir_read_begin(), f = initData->dir_read_end();
				j != f; ++j) {
			if (hasItem(globalVars, *j)) {
				globalVarsUsedInGlobalVarDef.insert(*j);
			}
		}
	}
}

/**
* @brief Computes @c globalVarsUsedInGlobalVarDef and @c funcUsedGlobalVarsMap
*        for each function (definitions and declarations).
*/
void GlobalToLocalOptimizer::computeUsedGlobalVars() {
	computeGlobalVarsUsedInGlobalVarDef();

	funcUsedGlobalVarsMap.clear();

	// Note that even though we optimize only defined functions, we need to know
	// whether a function that is only declared uses a global variable (this may
	// happen, even though it is very rare).

	// Do the computation, for every function.
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		funcUsedGlobalVarsMap[*i] = computeUsedGlobalVarsForFunc(*i);
	}
}

/**
* @brief Returns the set of used global variables in the given function.
*
* @a func may be a declaration or a definition.
*
* @par Preconditions
*  - @a func is non-null
*/
VarSet GlobalToLocalOptimizer::computeUsedGlobalVarsForFunc(
		ShPtr<Function> func) const {
	PRECONDITION_NON_NULL(func);

	ShPtr<FuncInfo> funcInfo(cio->getFuncInfo(func));
	VarSet usedGlobalVars;
	// For each global variable...
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		ShPtr<Variable> var((*i)->getVar());
		if (funcInfo->mayBeRead(var) || funcInfo->mayBeModified(var)) {
			usedGlobalVars.insert(var);
		}
	}
	return usedGlobalVars;
}

/**
* @brief Computes the sets of ``useful'' and ``useless'' global variables, @c
*        usefulGlobalVars and @c uselessGlobalVars.
*
* A global variable is called ``useful'' if it is a part of a computation
* that may impact the behavior of the program. For example, if a global
* variable is only assigned into other variables and none of these variables
* are actually used in a useful computation, it is ``useless''.
*
* @par Preconditions
*  - @c funcUsedGlobalVarsMap has been computed
*/
void GlobalToLocalOptimizer::computeUsefulAndUselessGlobalVars() {
	usefulGlobalVars.clear();
	uselessGlobalVars.clear();

	// Mark every variable that is used in the definition of other global
	// variables as useful. This is done so that we do not remove such
	// variables.
	addToSet(globalVarsUsedInGlobalVarDef, usefulGlobalVars);

	// Do not optimize external global variables because we may not have all
	// the available information for them (for example, in selective
	// decompilation, an external variable may be changed outside of the
	// decompiled code). To this end, mark them as useful global variables to
	// prevent their removal.
	addToSet(module->getExternalGlobalVars(), usefulGlobalVars);

	// First, we compute usefulGlobalVars. Then, we compute uselessGlobalVars
	// as the set difference globalVars - usefulGlobalVars. The reason is that
	// a direct computation of usefulGlobalVars is less computationally
	// intensive than the computation of uselessGlobalVars. Indeed, to see that
	// a global variable is useless, we have to check all the functions in the
	// module whereas to see that a global variable is useful, it suffices to
	// find a single function where it is useful.

	// Initialize a VarUsesVisitor and pre-compute all information to speedup
	// the computation of useful and useless global variables. This is done be
	// passing module as the last parameter of create().
	vuv = VarUsesVisitor::create(va, true, module);

	// For each global variable...
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		ShPtr<Variable> var((*i)->getVar());
		// For each function...
		for (auto j = module->func_definition_begin(),
				f = module->func_definition_end(); j != f; ++j) {
			if (isUsefulInFunc(var, *j)) {
				usefulGlobalVars.insert(var);

				// If the variable is useful in at least a single function,
				// then it cannot be useless, so we can move to the next global
				// variable. This speeds up the computation.
				break;
			}
		}
	}

	// uselessGlobalVars = globalVars - usefulGlobalVars
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		ShPtr<Variable> var((*i)->getVar());
		if (!hasItem(usefulGlobalVars, var)) {
			uselessGlobalVars.insert(var);
		}
	}
}

/**
* @brief Returns @c true if the given global variable @a var is useful in @a
*        func, @c false otherwise.
*
* See the description of computeUsefulAndUselessGlobalVars() for the definition
* of a ``useful global variable''.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
bool GlobalToLocalOptimizer::isUsefulInFunc(ShPtr<Variable> var,
		ShPtr<Function> func) const {
	PRECONDITION_NON_NULL(func);

	// The algorithm is an iterative fixed-point computation.
	//
	// During the first iteration, we obtain the set of all statements in which
	// the global variable is used. From this set, we compute the set of all
	// used variables in these statements. In the next iteration, we obtain the
	// set of all statements in which some of these variables are used, and so
	// on, until we reach a fixed-point.
	//
	// Furthermore, during this computation, we periodically check whether the
	// variable is useful; if so, then we return immediately to speedup the
	// computation.
	VarSet usedVars;
	usedVars.insert(var);
	StmtSet stmts;
	StmtSet oldStmts;
	do {
		oldStmts = stmts;

		// Get all statements in which used variables are (or may be) used.
		for (const auto &var : usedVars) {
			ShPtr<VarUses> varUses(vuv->getUses(var, func));
			addToSet(varUses->dirUses, stmts);
			addToSet(varUses->indirUses, stmts);
		}

		// Update usedVars.
		for (const auto &stmt : stmts) {
			// If the current statement implies that the variable is useful, we
			// can immediately return true.
			if (isStatementImplyingUsefulness(stmt)) {
				return true;
			}

			// From the call of isStatementImplyingUsefulness() above, we know
			// the form of the statement (see its description). To speed up the
			// computation, if the variable on the left-hand side is a global
			// variable, we may skip the variables read in the right-hand side
			// and do not include them into usedVars.
			if (hasItem(globalVars, cast<Variable>(getLhs(stmt)))) {
				continue;
			}

			ShPtr<ValueData> stmtData(va->getValueData(stmt));
			addToSet(stmtData->getDirAccessedVars(), usedVars);
			// Since there are no dereferences in the statement (see the
			// description of isStatementImplyingUsefulness()), we do not have
			// to include indirectly accessed variables.
		}
	} while (stmts != oldStmts);

	return false;
}

/**
* @brief Returns @c true if @a stmt is ``useful'', @c false otherwise.
*
* In the context of this optimization, a statement is ``useful'' if it is not
* an assign (or a variable-defining) statement assigning just variables or
* constants. Thus, if this function returns false, then @a stmt is of the form
* @code
* a = expr
* @endcode
* where @c a is a variable and @c expr is an expression not containing function
* calls, dereferences, address operators, and array accesses.
*/
bool GlobalToLocalOptimizer::isStatementImplyingUsefulness(
		ShPtr<Statement> stmt) const {
	// Check it is an assign or a variable-defining statement.
	if (!isVarDefOrAssignStmt(stmt)) {
		return true;
	}

	// Check that the left-hand side is a variable.
	if (!isa<Variable>(getLhs(stmt))) {
		return true;
	}

	// Check that there are no function calls.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	if (stmtData->hasCalls()) {
		return true;
	}

	// Check that there are no dereferences.
	if (stmtData->hasDerefs()) {
		return true;
	}

	// Check that there are no address operators.
	if (stmtData->hasAddressOps()) {
		return true;
	}

	return false;
}

/**
* @brief Returns @c true if the given global variable is used in the given
*        function, @c false otherwise.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
bool GlobalToLocalOptimizer::isUsedInFunc(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(func);

	return hasItem(funcUsedGlobalVarsMap[func], var);
}

/**
* @brief Returns @c true if the given global variable may be removed from the
*        module as unused, @c false otherwise.
*
* @par Preconditions
*  - @a var is non-null
*/
bool GlobalToLocalOptimizer::globalVarMayBeRemovedAsUnused(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	// The variable cannot be used in any function.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		if (isUsedInFunc(var, *i)) {
			return false;
		}
	}

	//
	// The variable cannot be used in any definition of a global variable. For
	// example, in the following code,
	//
	//   @a = global i32 1, align 4
	//   @b = global i32* @a, align 4
	//
	// variable @a cannot be removed.
	if (hasItem(globalVarsUsedInGlobalVarDef, var)) {
		return false;
	}

	// Note: Even though we do not optimize external global variables, we want
	//       to remove them if they are not used anywhere in the module. If we
	//       did not do that, all such external global variables would remain
	//       in the source code.

	return true;
}

/**
* @brief Returns @c true if the given global variable may be converted into a
*        local variable in the given function, @c false otherwise.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
bool GlobalToLocalOptimizer::globalVarMayBeConverted(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(func);

	// The global variable has to be used only in this function. Check all
	// functions whether var is used in them.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		if (*i != func && isUsedInFunc(var, *i)) {
			return false;
		}
	}

	// Do not allow conversion of external global variables because we may not
	// have all the available information for them (for example, in selective
	// decompilation, an external variable may be changed outside of the
	// decompiled code).
	if (var->isExternal()) {
		return false;
	}

	// There has to be an assignment into the global variable before its value
	// is read.
	return VarUseCFGTraversal::isDefinedPriorToEveryAccess(var,
		cio->getCFGForFunc(func), va);
}

} // namespace llvmir2hll
} // namespace retdec
