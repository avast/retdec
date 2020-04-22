/**
* @file src/llvmir2hll/llvm/llvmir2bir_converter/variables_manager.cpp
* @brief Implementation of VariablesManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/Twine.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/variables_manager.h"
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
* @brief Resets local variables in the variables manager.
*
* Also resets generator of new variable names.
*/
void VariablesManager::reset() {
	localVarsMap.clear();
	varNameGen->restart();
}

void VariablesManager::addGlobalValVarPair(llvm::Value *val, ShPtr<Variable> var) {
	globalVarsMap.emplace(val, var);
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

	if (auto gv = getGlobalVar(val)) {
		return gv;
	}

	return getOrCreateLocalVar(val);
}

/**
* @brief Assigns new name from generator to LLVM value.
*/
void VariablesManager::assignNameToValue(llvm::Value *val) const {
	// LLVM guarantees to choose unique name if the generated name is already
	// taken.
	val->setName(varNameGen->getNextVarName());
}

ShPtr<Variable> VariablesManager::getGlobalVar(llvm::Value *val) {
	auto fit = globalVarsMap.find(val);
	return fit != globalVarsMap.end() ? fit->second : nullptr;
}

/**
* @brief Returns the local variable for @a val.
*
* If local variable doesn't exist, new one will be created. Type of new created
* variable is unknown.
*/
ShPtr<Variable> VariablesManager::getOrCreateLocalVar(llvm::Value *val) {
	auto existingVarIt = localVarsMap.find(val);
	if (existingVarIt != localVarsMap.end()) {
		return existingVarIt->second;
	}

	Address a;
	if (auto* insn = llvm::dyn_cast<llvm::Instruction>(val)) {
		a = LLVMSupport::getInstAddress(insn);
	}

	auto var = Variable::create(val->getName(), UnknownType::create(), a);
	localVarsMap.emplace(val, var);
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
