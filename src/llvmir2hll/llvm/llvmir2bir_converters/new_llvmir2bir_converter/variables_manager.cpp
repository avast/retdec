/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/variables_manager.cpp
* @brief Implementation of VariablesManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/Twine.h>
#include <llvm/IR/Value.h>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/variables_manager.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/utils/container.h"

using retdec::utils::getValuesFromMap;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new variables manager.
*/
VariablesManager::VariablesManager(ShPtr<Module> resModule): localVarsMap(),
	varNameGen(NumVarNameGen::create()), resModule(resModule) {}

/**
* @brief Destructs the variables manager.
*/
VariablesManager::~VariablesManager() {}

/**
* @brief Resets local variables in the variables manager.
*
* Also resets generator of new variable names.
*/
void VariablesManager::reset() {
	localVarsMap.clear();
	varNameGen->restart();
}

/**
* @brief Returns the variable representing LLVM value @a val.
*
* If variable doesn't have it's own name, a new one is generated and assigned
* to it. The reason is, that all variables in BIR have to be named.
*/
ShPtr<Variable> VariablesManager::getVarByValue(llvm::Value *val) {
	if (!val->hasName()) {
		assignNameToValue(val);
	}

	return getVarByName(val->getName());
}

/**
* @brief Assigns new name from generator to LLVM value.
*/
void VariablesManager::assignNameToValue(llvm::Value *val) const {
	// LLVM guarantees to choose unique name if the generated name is already
	// taken.
	val->setName(varNameGen->getNextVarName());
}

/**
* @brief Returns the variable named by @a name.
*
* If resulting module contains function named by @a name, this function is
* returned as variable. If resulting module contains global variable named by
* @a name, this global variable is returned. Otherwise, variable named by
* @a name is returned.
*/
ShPtr<Variable> VariablesManager::getVarByName(const std::string &name) {
	if (auto func = resModule->getFuncByName(name)) {
		return func->getAsVar();
	} else if (auto globVar = resModule->getGlobalVarByName(name)) {
		return globVar;
	}

	return getOrCreateLocalVar(name);
}

/**
* @brief Returns the local variable named by @a name.
*
* If local variable doesn't exist, new one will be created. Type of new created
* variable is unknown.
*/
ShPtr<Variable> VariablesManager::getOrCreateLocalVar(const std::string &name) {
	auto existingVarIt = localVarsMap.find(name);
	if (existingVarIt != localVarsMap.end()) {
		return existingVarIt->second;
	}

	auto var = Variable::create(name, UnknownType::create());
	localVarsMap.emplace(name, var);
	return var;
}

/**
* @brief Returns set of all local variables.
*/
VarSet VariablesManager::getLocalVars() const {
	return getValuesFromMap(localVarsMap);
}

} // namespace llvmir2hll
} // namespace retdec
