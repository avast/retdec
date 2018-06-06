/**
* @file src/llvmir2hll/ir/module.cpp
* @brief Implementation of Module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>

#include "retdec/llvmir2hll/config/config.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"

using retdec::utils::FilterIterator;
using retdec::utils::filterTo;
using retdec::utils::hasItem;
using retdec::utils::mapGetValueOrDefault;
using retdec::utils::mapHasKey;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new module.
*
* @param[in] llvmModule Original module from which this module has been created.
* @param[in] identifier Identifier of the module.
* @param[in] semantics The used semantics.
* @param[in] config Configuration for the module.
*
* @par Preconditions
*  - both @a llvmModule and @a semantics are non-null
*/
Module::Module(const llvm::Module *llvmModule, const std::string &identifier,
		ShPtr<Semantics> semantics, ShPtr<Config> config):
	llvmModule(llvmModule), identifier(identifier), semantics(semantics),
	config(config), globalVars(), funcs(), debugVarNameMap() {
		PRECONDITION_NON_NULL(llvmModule);
		PRECONDITION_NON_NULL(semantics);
	}

/**
* @brief Destructs the module.
*/
Module::~Module() {}

/**
* @brief Adds a new global variable to the module.
*
* @param[in] var Variable to be added.
* @param[in] init Initializer of @a var.
*
* If the global variable already exists, it replaces its initializer with @a
* init.
*
* Time complexity: @c O(n), where @c n is the number of global variables in the
* module.
*/
void Module::addGlobalVar(ShPtr<Variable> var, ShPtr<Expression> init) {
	// Check whether the variable has already been added.
	for (auto i = globalVars.begin(), e = globalVars.end(); i != e; ++i) {
		if ((*i)->getVar() == var) {
			// It does, so just replace its initializer.
			(*i)->setInitializer(init);
			return;
		}
	}

	// The variable does not exist, so add it.
	globalVars.push_back(GlobalVarDef::create(var, init));
}

/**
* @brief Removes the given variable from the module.
*
* If the global variable does not exist, this function does nothing.
*
* Time complexity: @c O(n), where @c n is the number of global variables in the
* module.
*/
void Module::removeGlobalVar(ShPtr<Variable> var) {
	for (auto i = globalVars.begin(), e = globalVars.end(); i != e; ++i) {
		if ((*i)->getVar() == var) {
			globalVars.erase(i);
			return;
		}
	}
}

/**
* @brief Returns @c true if @a var is a global variable, @c false otherwise.
*
* Time complexity: @c O(n), where @c n is the number of global variables in the
* module.
*/
bool Module::isGlobalVar(ShPtr<Variable> var) const {
	for (auto i = globalVars.begin(), e = globalVars.end(); i != e; ++i) {
		if ((*i)->getVar() == var) {
			return true;
		}
	}
	return false;
}

/**
* @brief Is a variable with the given name global and stores a string literal?
*/
bool Module::isGlobalVarStoringStringLiteral(const std::string &varName) const {
	// Currently, we are only able to detect when a global variable stores a
	// wide string.
	return config->isGlobalVarStoringWideString(varName);
}

/**
* @brief Returns the initializer for the given global variable @a var.
*
* If @a var is not a global variable or if it has no initializer, the null
* pointer is returned.
*
* Time complexity: @c O(n), where @c n is the number of global variables in the
* module.
*/
ShPtr<Expression> Module::getInitForGlobalVar(ShPtr<Variable> var) const {
	for (auto i = globalVars.begin(), e = globalVars.end(); i != e; ++i) {
		if ((*i)->getVar() == var) {
			return (*i)->getInitializer();
		}
	}
	return ShPtr<Expression>();
}

/**
* @brief Returns the global variable named @a varName.
*
* @param[in] varName Name of the variable.
*
* If there is no global variable named @a varName, it returns the null pointer.
*
* Time complexity: @c O(n), where @c n is the number of global variables in the
* module.
*/
ShPtr<Variable> Module::getGlobalVarByName(const std::string &varName) const {
	for (auto i = globalVars.begin(), e = globalVars.end(); i != e; ++i) {
		if ((*i)->getVar()->getName() == varName) {
			return (*i)->getVar();
		}
	}

	// There is no global variable named varName.
	return ShPtr<Variable>();
}

/**
* @brief Returns all global variables (without their initializer).
*
* Time complexity: @c O(n), where @c n is the number of global variables in the
* module.
*/
VarSet Module::getGlobalVars() const {
	VarSet globalVarsSet;
	for (auto i = globalVars.begin(), e = globalVars.end(); i != e; ++i) {
		globalVarsSet.insert((*i)->getVar());
	}
	return globalVarsSet;
}

/**
* @brief Returns the set of external global variables.
*/
VarSet Module::getExternalGlobalVars() const {
	VarSet externalGlobalVars;
	for (auto &varDef : globalVars) {
		if (varDef->definesExternalVar()) {
			externalGlobalVars.insert(varDef->getVar());
		}
	}
	return externalGlobalVars;
}

/**
* @brief Returns the name of the register corresponding to the given global
*        variable.
*/
std::string Module::getRegisterForGlobalVar(ShPtr<Variable> var) const {
	return config->getRegisterForGlobalVar(var->getInitialName());
}

/**
* @brief Returns a description of the detected cryptographic pattern for the
*        given global variable.
*/
std::string Module::getDetectedCryptoPatternForGlobalVar(ShPtr<Variable> var) const {
	return config->getDetectedCryptoPatternForGlobalVar(var->getInitialName());
}

/**
* @brief Returns the underlying LLVM module of the module.
*/
const llvm::Module *Module::getLLVMModule() const {
	return llvmModule;
}

/**
* @brief Returns the identifier of the module.
*
* @param[in] stripDirs Strips all directories from the identifier (if any).
*/
std::string Module::getIdentifier(bool stripDirs) const {
	return stripDirs ? retdec::utils::stripDirs(identifier) : identifier;
}

/**
* @brief Returns the semantics of the module.
*/
ShPtr<Semantics> Module::getSemantics() const {
	return semantics;
}

/**
* @brief Returns @c true if the module contains at least one global variable,
*        @c false otherwise.
*/
bool Module::hasGlobalVars() const {
	return !globalVars.empty();
}

/**
* @brief Checks if the module contains a global variable with the given @a
*        name.
*/
bool Module::hasGlobalVar(const std::string &name) const {
	for (auto &varDef : globalVars) {
		if (varDef->getVar()->getName() == name) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns a constant iterator to the first global variable.
*/
Module::global_var_iterator Module::global_var_begin() const {
	return globalVars.begin();
}

/**
* @brief Returns a constant iterator past the last global variable.
*/
Module::global_var_iterator Module::global_var_end() const {
	return globalVars.end();
}

/**
* @brief Adds the given function to the module.
*
* @param[in] func Function to be added.
*
* If the function already exists in the module, nothing is done.
*/
void Module::addFunc(ShPtr<Function> func) {
	if (!hasItem(funcs, func)) {
		funcs.push_back(func);
	}
}

/**
* @brief Removes the given function from the module.
*
* If there is no matching function, nothing is removed.
*/
void Module::removeFunc(ShPtr<Function> func) {
	removeItem(funcs, func);
}

/**
* @brief Returns @c true if @a func exists in the module, @c false otherwise.
*
* @a func may be either a function definition or a function declaration.
*/
bool Module::funcExists(ShPtr<Function> func) const {
	return hasItem(funcs, func);
}

/**
* @brief Returns @c true if there is a main function in the module, @c false
*        otherwise.
*
* The name of the main function depends on the used semantics.
*/
bool Module::hasMainFunc() const {
	Maybe<std::string> mainFuncName(semantics->getMainFuncName());
	return mainFuncName ? hasFuncWithName(mainFuncName.get()) : false;
}

/**
* @brief Returns @c true if the given function is the main function, @c false
*        otherwise.
*
* The name of the main function depends on the used semantics.
*/
bool Module::isMainFunc(ShPtr<Function> func) const {
	Maybe<std::string> mainFuncName(semantics->getMainFuncName());
	return mainFuncName ? func->getName() == mainFuncName.get() : false;
}

/**
* @brief Returns the function named @a funcName.
*
* @param[in] funcName Name of the function.
*
* If there is no function named @a funcName, it returns the null pointer.
*/
ShPtr<Function> Module::getFuncByName(const std::string &funcName) const {
	for (const auto &func : funcs) {
		if (func->getName() == funcName) {
			return func;
		}
	}
	return ShPtr<Function>();
}

/**
* @brief Returns @c true if there is a function named @a funcName, @c false
*        otherwise.
*/
bool Module::hasFuncWithName(const std::string &funcName) const {
	return getFuncByName(funcName) != nullptr;
}

/**
* @brief Does the given variable correspond to a function?
*/
bool Module::correspondsToFunc(ShPtr<Variable> var) const {
	auto func = getFuncByName(var->getName());
	return func && var == func->getAsVar();
}

/**
* @brief Returns variables that correspond to functions in the module.
*/
VarSet Module::getVarsForFuncs() const {
	VarSet varsForFuncs;
	for (const auto &func : funcs) {
		varsForFuncs.insert(func->getAsVar());
	}
	return varsForFuncs;
}

/**
* @brief Returns the number of defined functions in the module.
*/
std::size_t Module::getNumOfFuncDefinitions() const {
	return std::count_if(funcs.begin(), funcs.end(),
		[](const auto &func) { return func->isDefinition(); }
	);
}

/**
* @brief Returns @c true if the module contains at least one function
*        definition, @c false otherwise.
*/
bool Module::hasFuncDefinitions() const {
	return std::any_of(funcs.begin(), funcs.end(),
		[](const auto &func) { return func->isDefinition(); }
	);
}

/**
* @brief Are there any user-defied functions in the module?
*/
bool Module::hasUserDefinedFuncs() const {
	for (auto &func : funcs) {
		if (config->isUserDefinedFunc(func->getInitialName())) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns all user-defined functions in the module.
*/
FuncSet Module::getUserDefinedFuncs() const {
	return getFuncsSatisfyingPredicate(
		[this](auto func) {
			return config->isUserDefinedFunc(func->getInitialName());
		}
	);
}

/**
* @brief Are there any statically linked functions in the module?
*/
bool Module::hasStaticallyLinkedFuncs() const {
	return hasFuncSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isStaticallyLinkedFunc(func->getInitialName());
		}
	);
}

/**
* @brief Returns all statically linked functions in the module.
*/
FuncSet Module::getStaticallyLinkedFuncs() const {
	return getFuncsSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isStaticallyLinkedFunc(func->getInitialName());
		}
	);
}

/**
* @brief Marks the given function as statically linked.
*/
void Module::markFuncAsStaticallyLinked(ShPtr<Function> func) {
	config->markFuncAsStaticallyLinked(func->getInitialName());
}

/**
* @brief Are there any dynamically linked functions in the module?
*/
bool Module::hasDynamicallyLinkedFuncs() const {
	return hasFuncSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isDynamicallyLinkedFunc(func->getInitialName());
		}
	);
}

/**
* @brief Returns all dynamically linked functions in the module.
*/
FuncSet Module::getDynamicallyLinkedFuncs() const {
	return getFuncsSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isDynamicallyLinkedFunc(func->getInitialName());
		}
	);
}

/**
* @brief Are there any syscall functions in the module?
*/
bool Module::hasSyscallFuncs() const {
	return hasFuncSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isSyscallFunc(func->getInitialName());
		}
	);
}

/**
* @brief Returns all syscall functions in the module.
*/
FuncSet Module::getSyscallFuncs() const {
	return getFuncsSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isSyscallFunc(func->getInitialName());
		}
	);
}

/**
* @brief Are there any syscall functions in the module?
*/
bool Module::hasInstructionIdiomFuncs() const {
	return hasFuncSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isInstructionIdiomFunc(func->getInitialName());
		}
	);
}

/**
* @brief Returns all syscall functions in the module.
*/
FuncSet Module::getInstructionIdiomFuncs() const {
	return getFuncsSatisfyingPredicate(
		[this](auto func) {
			return func->isDeclaration() &&
				config->isInstructionIdiomFunc(func->getInitialName());
		}
	);
}

/**
* @brief Is the given function exported?
*
* See the description of Config::isExportedFunc() for more details.
*/
bool Module::isExportedFunc(ShPtr<Function> func) const {
	return config->isExportedFunc(func->getInitialName());
}

/**
* @brief Returns the real name of the given function.
*
* If there is no real name attached to the given function, it returns the empty
* string.
*/
std::string Module::getRealNameForFunc(ShPtr<Function> func) const {
	return config->getRealNameForFunc(func->getInitialName());
}

/**
* @brief Returns a C declaration string for the given function.
*
* If there is no declaration string attached to the given function, it returns
* the empty string.
*/
std::string Module::getDeclarationStringForFunc(ShPtr<Function> func) const {
	return config->getDeclarationStringForFunc(func->getInitialName());
}

/**
* @brief Returns a comment for @a func.
*/
std::string Module::getCommentForFunc(ShPtr<Function> func) const {
	return config->getCommentForFunc(func->getInitialName());
}

/**
* @brief Returns a set of names of detected cryptographic patterns that the
*        given function uses.
*
* If the given function does not use any cryptographic patterns, the empty set
* is returned.
*/
StringSet Module::getDetectedCryptoPatternsForFunc(ShPtr<Function> func) const {
	return config->getDetectedCryptoPatternsForFunc(func->getInitialName());
}

/**
* @brief Returns the name of a function that @a func wraps.
*
* See the description of Config::getWrappedFunc() for more information.
*/
std::string Module::getWrappedFuncName(ShPtr<Function> func) const {
	return config->getWrappedFunc(func->getInitialName());
}

/**
* @brief Returns the demangled name of @a func.
*/
std::string Module::getDemangledNameOfFunc(ShPtr<Function> func) const {
	return config->getDemangledNameOfFunc(func->getInitialName());
}

/**
* @brief Returns a set of names of functions that were fixed by our LLVM-IR
*        fixer.
*/
StringSet Module::getNamesOfFuncsFixedWithLLVMIRFixer() const {
	return config->getFuncsFixedWithLLVMIRFixer();
}

/**
* @brief Returns a constant iterator to the first function.
*/
Module::func_iterator Module::func_begin() const {
	return funcs.begin();
}

/**
* @brief Returns a constant iterator past the last function.
*/
Module::func_iterator Module::func_end() const {
	return funcs.end();
}

/**
* @brief Returns a constant iterator to the first function definition.
*/
Module::func_filter_iterator Module::func_definition_begin() const {
	return func_filter_iterator(
		funcs,
		[](const auto &func) { return func->isDefinition(); }
	);
}

/**
* @brief Returns a constant iterator past the last function definition.
*/
Module::func_filter_iterator Module::func_definition_end() const {
	return func_filter_iterator(funcs.end());
}

/**
* @brief Returns a constant iterator to the first function declaration.
*/
Module::func_filter_iterator Module::func_declaration_begin() const {
	return func_filter_iterator(
		funcs,
		[](const auto &func) { return func->isDeclaration(); }
	);
}

/**
* @brief Returns a constant iterator past the last function declaration.
*/
Module::func_filter_iterator Module::func_declaration_end() const {
	return func_filter_iterator(funcs.end());
}

/**
* @brief Returns the address range for the given function.
*
* If there is no address range for @a func, @c NO_ADDRESS_RANGE is returned.
*/
AddressRange Module::getAddressRangeForFunc(ShPtr<Function> func) const {
	return config->getAddressRangeForFunc(func->getInitialName());
}

/**
* @brief Has the given function an address range?
*/
bool Module::hasAddressRange(ShPtr<Function> func) const {
	return getAddressRangeForFunc(func) != NO_ADDRESS_RANGE;
}

/**
* @brief Checks if all function definitions have an address range.
*/
bool Module::allFuncDefinitionsHaveAddressRange() const {
	for (const auto &func : funcs) {
		if (func->isDefinition() && !hasAddressRange(func)) {
			return false;
		}

	}
	return true;
}

/**
* @brief Returns the line range for the given function.
*
* If there is no line range for @a func, @c NO_LINE_RANGE is returned.
*/
LineRange Module::getLineRangeForFunc(ShPtr<Function> func) const {
	return config->getLineRangeForFunc(func->getInitialName());
}

/**
* @brief Has the given function a line range?
*/
bool Module::hasLineRange(ShPtr<Function> func) const {
	return getLineRangeForFunc(func) != NO_LINE_RANGE;
}

/**
* @brief Checks if all function definitions have a line range.
*/
bool Module::allFuncDefinitionsHaveLineRange() const {
	for (const auto &func : funcs) {
		if (func->isDefinition() && !hasLineRange(func)) {
			return false;
		}

	}
	return true;
}

/**
* @brief Is there a function satisfying the given predicate?
*/
bool Module::hasFuncSatisfyingPredicate(
		std::function<bool (ShPtr<Function>)> pred) const {
	for (auto &func : funcs) {
		if (pred(func)) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns a set of functions satisfying the given predicate.
*/
FuncSet Module::getFuncsSatisfyingPredicate(
		std::function<bool (ShPtr<Function>)> pred) const {
	return filterTo<FuncSet>(funcs, pred);
}

/**
* @brief Returns the name of a global variable from which the given local
*        variable comes from.
*
* If the given variable does not come from a global variable, the empty string
* is returned.
*/
std::string Module::comesFromGlobalVar(ShPtr<Function> func, ShPtr<Variable> var) const {
	return config->comesFromGlobalVar(func->getInitialName(), var->getInitialName());
}

/**
* @brief Have any classes been found?
*/
bool Module::hasClasses() const {
	return !config->getClassNames().empty();
}

/**
* @brief Returns the set of found class names.
*/
StringSet Module::getClassNames() const {
	return config->getClassNames();
}

/**
* @brief Returns the names of base classes of the given class.
*/
StringVector Module::getBaseClassNames(const std::string &cl) const {
	return config->getBaseClassNames(cl);
}

/**
* @brief Returns the demangled named of the given class.
*/
std::string Module::getDemangledNameOfClass(const std::string &cl) const {
	return config->getDemangledNameOfClass(cl);
}

/**
* @brief Returns the name of a class to which the given function belongs.
*
* If @a func does not belong to any class, the empty string is returned.
*/
std::string Module::getClassForFunc(ShPtr<Function> func) const {
	return config->getClassForFunc(func->getInitialName());
}

/**
* @brief Returns the type of the given function in the given class.
*
* The returned value is a textual representation, e.g. "constructor" or
* "virtual member function". If @a func does not belong to @c cl, the empty
* string is returned.
*/
std::string Module::getTypeOfFuncInClass(ShPtr<Function> func,
		const std::string &cl) const {
	return config->getTypeOfFuncInClass(func->getInitialName(), cl);
}

/**
* @brief Returns the name for the given global variable using debug information.
*
* If there is no name assigned to the given variable, the empty string is
* returned.
*/
std::string Module::getDebugNameForGlobalVar(ShPtr<Variable> var) const {
	return config->getDebugNameForGlobalVar(var->getInitialName());
}

/**
* @brief Returns the name for the given local variable using debug information.
*
* If there is no name assigned to the given variable, the empty string is
* returned.
*/
std::string Module::getDebugNameForLocalVar(ShPtr<Function> func,
		ShPtr<Variable> var) const {
	return config->getDebugNameForLocalVar(func->getInitialName(), var->getInitialName());
}

/**
* @brief Returns the name for the given variable using debug information.
*
* If there is no name assigned to the given variable, the empty string is
* returned.
*/
std::string Module::getDebugNameForVar(ShPtr<Variable> var) const {
	return mapGetValueOrDefault(debugVarNameMap, var);
}

/**
* @brief Is debugging information available?
*/
bool Module::isDebugInfoAvailable() const {
	return config->isDebugInfoAvailable();
}

/**
* @brief Returns the module name for the given function using debug
*        information.
*
* If there is no module name assigned to the given function, the empty string
* is returned.
*/
std::string Module::getDebugModuleNameForFunc(ShPtr<Function> func) const {
	return config->getDebugModuleNameForFunc(func->getInitialName());
}

/**
* @brief Has the given function assigned a module name from debug information?
*/
bool Module::hasAssignedDebugModuleName(ShPtr<Function> func) const {
	return !getDebugModuleNameForFunc(func).empty();
}

/**
* @brief Returns the set of all module names for all functions.
*
* If debug info is not available or there are no functions, the empty set is
* returned.
*/
StringSet Module::getDebugModuleNames() const {
	return config->getDebugModuleNames();
}

/**
* @brief Returns @c true if the given variable has assigned a name from debug
*        information, @c false otherwise.
*/
bool Module::hasAssignedDebugName(ShPtr<Variable> var) const {
	return mapHasKey(debugVarNameMap, var);
}

/**
* @brief Adds a name for the given variable using debug information.
*
* The new name overwrites any name that has already been set for @a var.
*/
void Module::addDebugNameForVar(ShPtr<Variable> var, const std::string &name) {
	debugVarNameMap[var] = name;
}

/**
* @brief Returns the release of the front-end.
*
* If there is no release, it returns the empty string.
*/
std::string Module::getFrontendRelease() const {
	return config->getFrontendRelease();
}

/**
* @brief Returns the number of functions detected in the front-end.
*/
std::size_t Module::getNumberOfFuncsDetectedInFrontend() const {
	return config->getNumberOfFuncsDetectedInFrontend();
}

/**
* @brief Returns the detected compiler/packer.
*
* If there is no detected compiler/packer, it returns the empty string.
*/
std::string Module::getDetectedCompilerOrPacker() const {
	return config->getDetectedCompilerOrPacker();
}

/**
* @brief Returns a set of functions that were selected to be decompiled but
*        were not found.
*/
StringSet Module::getSelectedButNotFoundFuncs() const {
	return config->getSelectedButNotFoundFuncs();
}

/**
* @brief Returns the detected language.
*
* If there is no detected language, it returns the empty string.
*/
std::string Module::getDetectedLanguage() const {
	return config->getDetectedLanguage();
}

} // namespace llvmir2hll
} // namespace retdec
