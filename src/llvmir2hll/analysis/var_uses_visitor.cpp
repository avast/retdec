/**
* @file src/llvmir2hll/analysis/var_uses_visitor.cpp
* @brief Implementation of VarUsesVisitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;
using retdec::utils::setUnion;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new provider.
*
* For the description of the parameters, see @c create().
*/
VarUsesVisitor::VarUsesVisitor(ShPtr<ValueAnalysis> va,
		bool enableCaching):
	OrderedAllVisitor(true, true), va(va), varUses(), precomputing(false),
	precomputingHasBeenDone(false), cachingEnabled(enableCaching), cache() {}

/**
* @brief Destructs the provider.
*/
VarUsesVisitor::~VarUsesVisitor() {}

/**
* @brief Returns @c true if @a var is used in @a func, @c false otherwise.
*
* @param[in] var Variable whose uses are obtained.
* @param[in] func Function whose body is checked.
* @param[in] doNotIncludeFirstUse Do not consider the first use of @a var to
*                                 be a use.
*
* See the description of @c getUses() for more details. If you want to just
* check whether a variable is used in a function and you don't care about the
* precise number/places of uses, use this function.
*
* If @c var may or must be indirectly used, such a use is also counted as a
* use.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
bool VarUsesVisitor::isUsed(ShPtr<Variable> var, ShPtr<Function> func,
		bool doNotIncludeFirstUse) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(func);

	// TODO Implement this function more efficiently?

	varUses = getUses(var, func);
	if (doNotIncludeFirstUse) {
		return (varUses->dirUses.size() + varUses->indirUses.size()) > 1;
	} else {
		return !varUses->dirUses.empty() || !varUses->indirUses.empty();
	}
}

/**
* @brief Returns all uses of @a var in @a func.
*
* @param[in] var Variable whose uses are obtained.
* @param[in] func Function whose body is checked.
*
* For example, let @c var1 be a variable used in the following statement
* @code
* func(1, var1 + var2, "test");
* @endcode
* Then, this function obtains obtains
* @code
* func(1, var1 + var2, "test");
* @endcode
*
* A definition of a variable is also considered to be a use. Function
* parameters are skipped. Indirect uses are also included in the returned
* result.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
ShPtr<VarUses> VarUsesVisitor::getUses(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(func);

	// Have we already computed this piece of information?
	if (cachingEnabled) {
		varUses = cache[func][var];
		if (varUses) {
			return varUses;
		}
	}

	// Compute the uses.
	varUses = ShPtr<VarUses>(new VarUses(var, func));
	this->var = var;
	this->func = func;
	restart(); // We have to clear accessedStmts().
	visitStmt(this->func->getBody());

	// Should we cache the computed result?
	if (cachingEnabled) {
		cache[func][var] = varUses;
	}

	return varUses;
}

/**
* @brief Enables caching.
*
* It also clears the cache of the already cached results.
*/
void VarUsesVisitor::enableCaching() {
	cachingEnabled = true;
	clearCache();
}

/**
* @brief Disables caching.
*
* It also clears the cache of the already cached results.
*/
void VarUsesVisitor::disableCaching() {
	cachingEnabled = false;
	clearCache();
}

/**
* @brief Clears the cache of the already cached results.
*/
void VarUsesVisitor::clearCache() {
	cache.clear();
	precomputingHasBeenDone = false;
}

/**
* @brief Returns @c true if caching is enabled, @c false otherwise.
*/
bool VarUsesVisitor::isCachingEnabled() const {
	return cachingEnabled;
}

/**
* @brief Forces cache update (a new statement has been added to a function).
*
* If caching is disabled, it does nothing. Otherwise, the function recomputes
* what is necessary to recompute.
*
* <b>Important note</b>: The following sets of uses may be modified when this
* function is called:
*  - @c dirUses
*  - @c indirUses
* If you are iterating over any of these sets while calling this function, you
* have to first create a copy of the set and iterate over this set. Otherwise,
* the result is undefined.
*
* @par Preconditions
*  - @a stmt and @a func are non-null
*/
void VarUsesVisitor::stmtHasBeenAdded(ShPtr<Statement> stmt,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(func);

	if (!cachingEnabled) {
		return;
	}

	// Get all variables used in the new statement.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	VarSet dirUsedVars(stmtData->getDirAccessedVars());
	VarSet indirUsedVars(setUnion(
		stmtData->getMayBeAccessedVars(),
		stmtData->getMustBeAccessedVars()));

	// Go over all variables used in the function. If the current variable is
	// used in the new statement, update its uses.
	for (const auto &p : cache[func]) {
		// Directly used variables.
		if (hasItem(dirUsedVars, p.first)) {
			p.second->dirUses.insert(stmt);
			dirUsedVars.erase(p.first);
		}
		// Indirectly used variables.
		if (hasItem(indirUsedVars, p.first)) {
			p.second->indirUses.insert(stmt);
			indirUsedVars.erase(p.first);
		}
	}

	// If there are some variables left, it means that these haven't been used
	// in the function before the statement was added. Add them.
	// Directly used variables.
	for (const auto &var : dirUsedVars) {
		ShPtr<VarUses> varUses(new VarUses(var, func));
		varUses->dirUses.insert(stmt);
		cache[func][var] = varUses;
	}
	// Indirectly used variables.
	for (const auto &var : indirUsedVars) {
		ShPtr<VarUses> varUses(new VarUses(var, func));
		varUses->indirUses.insert(stmt);
		cache[func][var] = varUses;
	}
}

/**
* @brief Forces cache update (the given statement in the given function has
*        been altered).
*
* If caching is disabled, it does nothing. Otherwise, the function recomputes
* what is necessary to recompute.
*
* <b>Important note</b>: The following sets of uses may be modified when this
* function is called:
*  - @c dirUses
*  - @c indirUses
* If you are iterating over any of these sets while calling this function, you
* have to first create a copy of the set and iterate over this set. Otherwise,
* the result is undefined.
*
* @par Preconditions
*  - @a stmt and @a func are non-null
*/
void VarUsesVisitor::stmtHasBeenChanged(ShPtr<Statement> stmt,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(func);

	if (!cachingEnabled) {
		return;
	}

	// Get all variables used in the new statement.
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	const VarSet &dirUsedVars(stmtData->getDirAccessedVars());
	const VarSet &indirUsedVars(setUnion(
		stmtData->getMayBeAccessedVars(),
		stmtData->getMustBeAccessedVars()));

	// Go over all variables used in the function and remove the statement from
	// the uses of all variables in the function which are not used in the
	// statement. Notice that this has to be done only for cached variables.
	for (const auto &p : cache[func]) {
		// Direct uses.
		p.second->dirUses.erase(stmt);
		if (hasItem(dirUsedVars, p.first)) {
			p.second->dirUses.insert(stmt);
		}
		// Indirect uses.
		p.second->indirUses.erase(stmt);
		if (hasItem(indirUsedVars, p.first)) {
			p.second->indirUses.insert(stmt);
		}
	}
}

/**
* @brief Forces cache update (the given statement in the given function has
*        been removed).
*
* If caching is disabled, it does nothing. Otherwise, the function recomputes
* what is necessary to recompute.
*
* <b>Important note</b>: The following sets of uses may be modified when this
* function is called:
*  - @c dirUses
*  - @c indirUses
* If you are iterating over any of these sets while calling this function, you
* have to first create a copy of the set and iterate over this set. Otherwise,
* the result is undefined.
*
* @par Preconditions
*  - @a stmt and @a func are non-null
*/
void VarUsesVisitor::stmtHasBeenRemoved(ShPtr<Statement> stmt,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(func);

	if (!cachingEnabled) {
		return;
	}

	// Remove the statement from the uses of all variables in the function.
	// TODO Is this way faster than obtaining all variables used in stmt and
	//      then updating only the uses of these variables?
	for (const auto &p : cache[func]) {
		p.second->dirUses.erase(stmt);
		p.second->indirUses.erase(stmt);
	}
}

/**
* @brief Creates a new visitor.
*
* @param[in] va The used analysis of values.
* @param[in] enableCaching If @c true, it caches the results returned by
*                          getUses() until restartCache() or disableCaching()
*                          is called. This may speed
* up subsequent calls to getUses().
* @param[in] module If non-null, this function pre-computes information for
*                   every function and variable in the module.
*
* @par Preconditions
*  - @a va is non-null
*  - if @a module is non-null, @c enableCaching has to be @c true
*  - @a va is in a valid state
*
* All methods of this class leave @a va in a valid state.
*/
ShPtr<VarUsesVisitor> VarUsesVisitor::create(ShPtr<ValueAnalysis> va,
		bool enableCaching, ShPtr<Module> module) {
	PRECONDITION_NON_NULL(va);
	PRECONDITION(!module || enableCaching,
		"when module is non-null, caching has to be enabled");
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	ShPtr<VarUsesVisitor> visitor(new VarUsesVisitor(va, enableCaching));

	// Pre-compute everything if requested.
	if (module) {
		visitor->precomputeEverything(module);
	}

	return visitor;
}

/**
* @brief Pre-computes uses of variables in all functions of the given module.
*/
void VarUsesVisitor::precomputeEverything(ShPtr<Module> module) {
	precomputing = true;

	// For every function in the module...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		func = *i;

		// If a global variable is not used in a function, we normally wouldn't
		// create a cache entry for it. However, then, when calling getUses(),
		// getUses() would act as if we haven't precomputed everything. To
		// this end, we initialize an empty VarUses for every global variable.
		for (auto j = module->global_var_begin(), f = module->global_var_end();
				j != f; ++j) {
			cache[func][(*j)->getVar()] = ShPtr<VarUses>(
				new VarUses((*j)->getVar(), func));
		}

		// Do the same for all function's arguments (there may be arguments
		// which are never used).
		for (const auto &param : func->getParams()) {
			cache[func][param] = ShPtr<VarUses>(new VarUses(param, func));
		}

		restart();
		visitStmt(func->getBody());
	}

	precomputingHasBeenDone = true;
	precomputing = false;
}

/**
* @brief Finds uses of @c var in the given statement and stores them.
*
* It doesn't check nested statements or successors.
*/
void VarUsesVisitor::findAndStoreUses(ShPtr<Statement> stmt) {
	ShPtr<ValueData> stmtData(va->getValueData(stmt));
	if (precomputing) {
		// We are pre-computing everything.

		// Directly used variables.
		for (auto i = stmtData->dir_all_begin(), e = stmtData->dir_all_end();
				i != e; ++i) {
			ShPtr<VarUses> &varUses(cache[func][*i]);
			if (!varUses) {
				varUses = ShPtr<VarUses>(new VarUses(*i, func));
			}
			varUses->dirUses.insert(stmt);
		}

		// Indirectly used variables.
		VarSet indirUsedVars;
		addToSet(stmtData->getMayBeAccessedVars(), indirUsedVars);
		addToSet(stmtData->getMustBeAccessedVars(), indirUsedVars);
		// For every indirectly used variable...
		for (const auto &var : indirUsedVars) {
			ShPtr<VarUses> &varUses(cache[func][var]);
			if (!varUses) {
				varUses = ShPtr<VarUses>(new VarUses(var, func));
			}
			varUses->indirUses.insert(stmt);
		}
	} else {
		// We are not pre-computing.

		// Is the variable used directly?
		if (stmtData->isDirAccessed(var)) {
			varUses->dirUses.insert(stmt);
		}

		// Is the variable used indirectly?
		if (hasItem(stmtData->getMayBeAccessedVars(), var) ||
				hasItem(stmtData->getMustBeAccessedVars(), var)) {
			varUses->indirUses.insert(stmt);
		}
	}
}

/**
* @brief Dumps @c cache to standard error.
*
* This function should be used only for debugging purposes.
*/
void VarUsesVisitor::dumpCache() {
	llvm::errs() << "[VarUsesVisitor] Cache:\n";
	for (auto i = cache.begin(), e = cache.end(); i != e; ++i) {
		llvm::errs() << "    " << i->first->getName() << ":\n";
		for (auto j = i->second.begin(), f = i->second.end(); j != f ; ++j) {
			llvm::errs() << "        " << j->first->getName() << ":\n";
			llvm::errs() << "            dir: ";
			dump(j->second->dirUses, dumpFuncGetTextRepr<ShPtr<Statement>>);
			llvm::errs() << "            indir: ";
			dump(j->second->indirUses, dumpFuncGetTextRepr<ShPtr<Statement>>);
		}
	}
	llvm::errs() << "\n";
}

void VarUsesVisitor::visit(ShPtr<AssignStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<VarDefStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<CallStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<ReturnStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<EmptyStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<IfStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<SwitchStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<WhileLoopStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<ForLoopStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<UForLoopStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<BreakStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<ContinueStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<GotoStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

void VarUsesVisitor::visit(ShPtr<UnreachableStmt> stmt) {
	findAndStoreUses(stmt);
	OrderedAllVisitor::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
