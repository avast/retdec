/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/vars_handler.cpp
* @brief Implementation of VarsHandler.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/ErrorHandling.h>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/vars_handler.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"

using namespace retdec::llvm_support;

using retdec::utils::hasItem;
using retdec::utils::mapGetValueOrDefault;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new variables handler.
*
* @param[in] resModule Resulting module.
* @param[in] varNameGen Generator of variable names.
*/
VarsHandler::VarsHandler(ShPtr<Module> resModule, ShPtr<VarNameGen> varNameGen):
	resModule(resModule), varNameGen(varNameGen), anonVarNames(),
	localVars(), allocatedVarTypes(), convertingGlobalVars(false) {}

/**
* @brief Destructs the variables handler.
*/
VarsHandler::~VarsHandler() {}

/**
* @brief Remembers that we are going to convert global variables.
*
* This function has to be called before converting global variables.
*/
void VarsHandler::startConvertingGlobalVars() {
	convertingGlobalVars = true;
}

/**
* @brief Remembers that we have stopped converting global variables.
*
* This function has to be called after converting global variables.
*/
void VarsHandler::stopConvertingGlobalVars() {
	convertingGlobalVars = false;
}

/**
* @brief Resets containers and counters in the handler.
*/
void VarsHandler::reset() {
	localVars.clear();
	allocatedVarTypes.clear();
	varNameGen->restart();
	anonVarNames.clear();
}

/**
* @brief Returns the variable named by @a varName.
*
* @param[in] varName Name of the requested variable.
*
* If @a varName is the name of an existing global variable, local variable
* (including function parameters), or a function, this variable is returned. If
* there is no variable named @a varName, this function creates a new one, adds
* it either to resModule as a global variable (when @c convertingGlobalVars is
* @c true), or into @c localVars (when @c convertingGlobalVars is @c false),
* and returns it.
*/
ShPtr<Variable> VarsHandler::getVariableByName(const std::string &varName) {
	// Try local variables (function parameters are included).
	if (!convertingGlobalVars && hasItem(localVars, varName)) {
		return localVars[varName];
	}

	// Try global variables (this should be done after checking local
	// variables).
	if (auto globVar = resModule->getGlobalVarByName(varName)) {
		return globVar;
	}

	// Try functions.
	if (auto func = resModule->getFuncByName(varName)) {
		return func->getAsVar();
	}

	// Create a new variable.
	// Create the variable of UnknownType. A proper type will be set later.
	auto var = Variable::create(varName, UnknownType::create());
	if (convertingGlobalVars) {
		resModule->addGlobalVar(var);
	} else {
		localVars[varName] = var;
	}
	return var;
}

/**
* @brief Returns a string representation of the given value @a v (it's name).
*/
std::string VarsHandler::getValueName(const llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	std::string varName(v->getName());

	// If the variable does not have its original name, assign a new, unique
	// name to it.
	if (varName.empty()) {
		if (hasItem(anonVarNames, v)) {
			// This variable already has an assigned name, so use it.
			varName = anonVarNames[v];
		} else {
			// Generate a new name for this variable.
			// varNameGen->getNextVarName() automatically resets itself when
			// there are no available names left (this should not happen in
			// practice, though).
			anonVarNames[v] = varName = varNameGen->getNextVarName();
		}
	}

	return varName;
}

/**
* @brief Adds a new local variable.
*
* @param[in] var Variable to be added.
*
* If there already exists a local variable named @c var->getName(), this
* function does nothing.
*/
void VarsHandler::addLocalVar(ShPtr<Variable> var) {
	if (!hasItem(localVars, var->getName())) {
		localVars[var->getName()] = var;
	}
}

/**
* @brief Returns @c true if there is a local variable named @a varName, @c
*        false otherwise.
*
* @param[in] varName Name of the local variable variable to be checked.
*/
bool VarsHandler::localVarExists(const std::string &varName) const {
	return hasItem(localVars, varName);
}

/**
* @brief Returns all local variables, including parameters.
*/
VarSet VarsHandler::getLocalVars() const {
	VarSet result;
	for (const auto &p : localVars) {
		result.insert(p.second);
	}
	return result;
}

/**
* @brief Adds a type for the given allocated LLVM variable.
*
* @param[in] var LLVM variable.
* @param[in] varType Type of @a var.
*
* If there already exists a var @a var, it replaces the originally stored type
* with @a varType.
*/
void VarsHandler::addAllocatedVarType(llvm::Value *var, llvm::Type *varType) {
	allocatedVarTypes[var] = varType;
}

/**
* @brief Returns the type of @a var.
*
* @param[in] var LLVM variable.
*
* If there is no type corresponding to @a var, it returns the null pointer.
*/
llvm::Type *VarsHandler::getAllocatedVarType(llvm::Value *var) const {
	return mapGetValueOrDefault(allocatedVarTypes, var, nullptr);
}

} // namespace llvmir2hll
} // namespace retdec
