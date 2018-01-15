/**
* @file src/llvmir2hll/var_renamer/var_renamer.cpp
* @brief Implementation of VarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cctype>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"

using retdec::utils::hasItem;
using retdec::utils::mapGetValueOrDefault;
using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new variable renamer.
*
* @param[in] varNameGen Used generator of variable names (if applicable).
* @param[in] useDebugNames Should we use variable names from debugging
*                          information?
*
* @par Preconditions
*  - @a varNameGen is non-null
*/
VarRenamer::VarRenamer(ShPtr<VarNameGen> varNameGen, bool useDebugNames):
	varNameGen(varNameGen), useDebugNames(useDebugNames), module(),
	globalVars(), renamedVars(), globalVarsNames(), localVarsNames(),
	currFunc() {
		PRECONDITION_NON_NULL(varNameGen);
	}

/**
* @brief Destructor.
*/
VarRenamer::~VarRenamer() {}

/**
* @brief Renames variables in the given module according to the settings set
*        when constructing the renamer.
*
* @param[in,out] module Module whose variables are renamed.
*
* Before that, however, it restarts the variable name generator passed when
* creating the renamer.
*
* Function names are not renamed.
*/
void VarRenamer::renameVars(ShPtr<Module> module) {
	this->module = module;
	globalVars = module->getGlobalVars();
	storeFuncsByName();
	varNameGen->restart();
	doVarsRenaming();
}

/**
* @brief Assigns @a name to the given variable @a var, possibly in the given
*        function.
*
* Before the name is assigned, ensureNameUniqueness() is called to prevent name
* clashes.
*
* Data members, like @a renamedVars, are appropriately set.
*
* Note that this function does not check whether the variable has already been
* renamed. It simply renames it.
*
* If renaming a global variable or a function, pass the null pointer as the
* third argument.
*
* @par Preconditions
*  - @a var is non-null
*  - @a name is non-empty
*  - if @a var is a local variable or a function parameter, @a func has to be
*    non-null
*/
void VarRenamer::assignName(ShPtr<Variable> var, const std::string &name,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION(!name.empty(), "the name cannot be empty");

	// Check whether renaming the variable to name would not introduce a name
	// clash. If so, then generate a new name (see the function's description).
	std::string newName(ensureNameUniqueness(var, name, func));
	var->setName(newName);

	// Update data members.
	renamedVars.insert(var);
	if (isGlobalVar(var)) {
		globalVarsNames.insert(var->getName());
	} else {
		ASSERT_MSG(func, "when renaming a local variable, its function has to "
			"be passed as the third argument");
		localVarsNames[func].insert(var->getName());
	}
}

/**
* @brief Assigns the name from debug information (if available) to the given
*        variable.
*
* @param[in] var  Variable to be (possibly) renamed.
* @param[in] func Function of the variable (if @a var is a local variable or a
*                 parameter).
*
* Data members, like @a renamedVars, are appropriately set.
*
* @par Preconditions
*  - @a var is non-null
*  - if @a var is a local variable or a function parameter, @a func has to be
*    non-null
*/
void VarRenamer::assignNameFromDebugInfoIfAvail(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	std::string varDebugName(module->getDebugNameForVar(var));
	if (varDebugName.empty()) {
		return;
	}

	// Ensure that we have a valid identifier before assigning it.
	varDebugName = makeIdentifierValid(varDebugName);

	assignName(var, varDebugName, func);
}

/**
* @brief Returns @c true if the given variable is global, @c false otherwise.
*
* @par Preconditions
*  - @a var is non-null
*/
bool VarRenamer::isGlobalVar(ShPtr<Variable> var) const {
	PRECONDITION_NON_NULL(var);

	return hasItem(globalVars, var);
}

/**
* @brief Returns @c true if the given variable corresponds to a function, @c
*        false otherwise.
*
* @par Preconditions
*  - @a var is non-null
*/
bool VarRenamer::isFunc(ShPtr<Variable> var) const {
	PRECONDITION_NON_NULL(var);

	return module->correspondsToFunc(var);
}

/**
* @brief Returns @c true if the given variable has already been renamed, @c
*        false otherwise.
*
* @par Preconditions
*  - @a var is non-null
*/
bool VarRenamer::hasBeenRenamed(ShPtr<Variable> var) const {
	PRECONDITION_NON_NULL(var);

	return hasItem(renamedVars, var);
}

/**
* @brief Returns @c true if the given name has already been assigned, @c false
*        otherwise.
*
* @param[in] name Name that is being checked.
* @param[in] func If non-null, it does the check in terms of this function.
*
* More precisely, it returns @c true if naming a variable by @a name would
* introduce a name clash.
*/
bool VarRenamer::nameExists(const std::string &name, ShPtr<Function> func) const {
	// Global names.
	if (hasItem(globalVarsNames, name) || getFuncByName(name)) {
		return true;
	}

	// Local names.
	if (func) {
		auto it = localVarsNames.find(func);
		if (it != localVarsNames.end()) {
			return hasItem(it->second, name);
		}
	}

	return false;
}

/**
* @brief Returns a function with the given name.
*
* If there is no function with the given name, the null pointer is returned.
*/
ShPtr<Function> VarRenamer::getFuncByName(const std::string &name) const {
	// This is a "wrapper" around module->getFuncByName() to speedup the
	// renaming (it is a bottleneck, I have measured it).
	return mapGetValueOrDefault(funcsByName, name);
}

/**
* @brief Populates the @c funcsByName map.
*/
void VarRenamer::storeFuncsByName() {
	funcsByName.clear();
	for (auto i = module->func_begin(), e = module->func_end();
			i != e; ++i) {
		funcsByName[(*i)->getName()] = *i;
	}
}

/**
* @brief Ensures that the given name (possibly in the given function) is
*        unique.
*
* @param[in] var  Variable which is to be renamed.
* @param[in] name Name to be checked.
* @param[in] func Function of the variable (if @a var is a local variable or a
*                 parameter).
*
* @return Either @c name (if @a name is unique) or a new generated name (if @a
*         name is not unique).
*
* If renaming a global variable, pass the null pointer as the third argument.
*
* @par Preconditions
*  - @a var is non-null
*  - @a name is non-empty
*  - if @a var is a local variable or a function parameter, @a func has to be
*    non-null
*/
std::string VarRenamer::ensureNameUniqueness(ShPtr<Variable> var,
		const std::string &name, ShPtr<Function> func) {
	if (!nameExists(name, func)) {
		return name;
	}

	return generateUniqueName(var, name, func);
}

/**
* @brief Generates a new, unique name based on the given name.
*
* @param[in] var  Variable which is to be renamed.
* @param[in] name Name to be checked.
* @param[in] func Function of the variable (if @a var is a local variable or a
*                 parameter).
*
* @return A new, unique name based on @c name.
*
* When @a name clashes with an existing name, the following approach is used to
* handle the clash. When @a name ends with a digit, underscores are appended
* after the name until a name without a clash is found. Otherwise, if @a name
* does not end with a digit, a number is appended after it (2, 3, ...).
*
* If renaming a global variable, pass the null pointer as the third argument.
*/
std::string VarRenamer::generateUniqueName(ShPtr<Variable> var,
		const std::string &name, ShPtr<Function> func) {
	std::string newName(name);
	if (std::isdigit(name.back())) {
		// The name ends with a number -> append underscores.
		do {
			newName += "_";
		} while (nameExists(newName, func));
	} else {
		// The name does not end with a number -> append numbers.
		unsigned varNum = 2;
		do {
			newName = name + toString(varNum++);
		} while (nameExists(newName, func));
	}
	return newName;
}

/**
* @brief Assigns real names to all functions, where available.
*
* We use real names to circumvent the fact that two variables (functions or
* global variables) cannot have the same name in LLVM IR. Instead of handling
* this on the LLVM IR level, we handle this here, in back-end.
*/
void VarRenamer::assignRealNamesToFuncs() {
	// For every function...
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		auto realName = module->getRealNameForFunc(*i);
		if (!realName.empty()) {
			assignNameToFunc(*i, realName);
		}
	}
}

/**
* @brief Assigns @a name to the given function @a func.
*
* Behaves as @c assignName().
*/
void VarRenamer::assignNameToFunc(ShPtr<Function> func, const std::string &name) {
	PRECONDITION_NON_NULL(func);
	PRECONDITION(!name.empty(), "the name cannot be empty");

	auto origName = func->getName();

	// Check whether renaming the variable to name would not introduce a name
	// clash. If so, then generate a new name.
	auto newName = ensureNameUniqueness(func->getAsVar(), name);
	func->setName(newName);

	// Update data members.
	renamedVars.insert(func->getAsVar());
	funcsByName.erase(origName);
	funcsByName[newName] = func;
}

/**
* @brief Renames the variables in @c module.
*
* By default, this function does the following:
*  - initializes
*  - it assigns real names to all functions (when available)
*  - if @c useDebugNames is @c true, it renames all variables by using debug
*    information from the module by calling renameUsingDebugNames()
*  - it renames all global variables by calling renameGlobalVars()
*  - it renames all local variables by calling renameVarsInFuncs()
*/
void VarRenamer::doVarsRenaming() {
	assignRealNamesToFuncs();
	if (useDebugNames) {
		renameUsingDebugNames();
	}
	renameGlobalVars();
	renameVarsInFuncs();
}

/**
* @brief Renames all variables in the module by using the assigned names from
*        debug information.
*/
void VarRenamer::renameUsingDebugNames() {
	// For every global variable...
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		assignNameFromDebugInfoIfAvail((*i)->getVar());
	}

	// For every function...
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		// For every local variable of the function, including function
		// parameters...
		VarSet localVars((*i)->getLocalVars(true));
		for (const auto &localVar : localVars) {
			assignNameFromDebugInfoIfAvail(localVar, *i);
		}
	}
}

/**
* @brief Renames all global variables in the module.
*
* By default, it calls renameGlobalVar() on every global variable in the module
* that does has not yet been renamed. Before that, it sorts them by their
* original name to make the renaming deterministic.
*/
void VarRenamer::renameGlobalVars() {
	// Sort the variables by their original the make the renaming
	// deterministic.
	VarSet globalVarsSet(module->getGlobalVars());
	VarVector globalVars(globalVarsSet.begin(), globalVarsSet.end());
	sortByName(globalVars);

	// For every global variable...
	for (const auto &var : globalVars) {
		if (!hasBeenRenamed(var)) {
			renameGlobalVar(var);
		}
	}
}

/**
* @brief Renames the given global variable.
*
* By default, it uses @c varNameGen to generate a new name for the variable.
*
* @par Preconditions
*  - @a var is non-null
*/
void VarRenamer::renameGlobalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	assignName(var, varNameGen->getNextVarName());
}

/**
* @brief Renames the variables in all functions.
*
* By default, it calls renameVarsInFunc() on every function in the module,
* including function declarations.
*/
void VarRenamer::renameVarsInFuncs() {
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		renameVarsInFunc(*i);
	}
}

/**
* @brief Renames variables in the given function.
*
* By default, it sets @c currFunc, calls renameFuncParam() on every function
* parameter that has not yet been renamed. Then, if @a func is a definition, it
* calls @c visitStmt(func->getBody()) to call renameFuncLocalVar() on every
* local variable in the function.
*
* @par Preconditions
*  - @a func is non-null
*/
void VarRenamer::renameVarsInFunc(ShPtr<Function> func) {
	PRECONDITION_NON_NULL(func);

	currFunc = func;
	restart();

	// For every parameter...
	for (const auto &param : func->getParams()) {
		if (!hasBeenRenamed(param)) {
			renameFuncParam(param, func);
		}
	}

	if (func->isDefinition()) {
		// Rename local variables.
		visitStmt(func->getBody());
	}
}

/**
* @brief Renames the given parameter @a var of function @a func.
*
* By default, it uses @c varNameGen to generate a new name for the variable.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
void VarRenamer::renameFuncParam(ShPtr<Variable> var, ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(func);

	assignName(var, varNameGen->getNextVarName(), func);
}

/**
* @brief Renames the given local variable @a var of function @a func.
*
* By default, it uses @c varNameGen to generate a new name for the variable.
*
* @par Preconditions
*  - @a var and @a func are non-null
*/
void VarRenamer::renameFuncLocalVar(ShPtr<Variable> var, ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(func);

	assignName(var, varNameGen->getNextVarName(), func);
}

void VarRenamer::visit(ShPtr<Variable> var) {
	// Do not rename already renamed variables.
	if (hasBeenRenamed(var)) {
		return;
	}

	// Do not rename function names.
	if (getFuncByName(var->getName())) {
		return;
	}

	renameFuncLocalVar(var, currFunc);
}

} // namespace llvmir2hll
} // namespace retdec
