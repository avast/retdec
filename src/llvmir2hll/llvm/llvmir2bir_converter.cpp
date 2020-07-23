/**
* @file src/llvmir2hll/llvm/llvmir2bir_converter.cpp
* @brief Implementation of LLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Module.h>

#include "retdec/llvmir2hll/config/config.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/structure_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/variables_manager.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/utils/io/log.h"

using namespace retdec::utils::io;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new converter.
*
* For more details, see create().
*/
LLVMIR2BIRConverter::LLVMIR2BIRConverter(llvm::Pass *basePass):
	basePass(basePass), optionStrictFPUSemantics(false),
	enableDebug(false), converter(),
	llvmModule(nullptr), resModule(), structConverter(), variablesManager() {}

/**
* @brief Creates a new converter.
*
* @param[in] basePass Pass that instantiates a concrete converter.
*
* @par Preconditions
*  - @a basePass is non-null
*/
ShPtr<LLVMIR2BIRConverter> LLVMIR2BIRConverter::create(llvm::Pass *basePass) {
	return ShPtr<LLVMIR2BIRConverter>(new LLVMIR2BIRConverter(basePass));
}

/**
* @brief Enables/disables the use of strict FPU semantics.
*
* @param[in] strict If @c true, enables the use of strict FPU semantics. If @c
*                   false, disables the use of strict FPU semantics.
*/
void LLVMIR2BIRConverter::setOptionStrictFPUSemantics(bool strict) {
	optionStrictFPUSemantics = strict;
}

/**
* @brief Converts the given LLVM module into a module in BIR.
*
* @param[in] llvmModule LLVM module to be converted.
* @param[in] moduleName Identifier of the resulting module.
* @param[in] semantics The used semantics.
* @param[in] config Configuration for the module.
* @param[in] enableDebug If @c true, debugging messages will be emitted.
*
* @par Preconditions
*  - both @a llvmModule and @a semantics are non-null
*/
ShPtr<Module> LLVMIR2BIRConverter::convert(llvm::Module *llvmModule,
		const std::string &moduleName, ShPtr<Semantics> semantics,
		ShPtr<Config> config, bool enableDebug) {
	PRECONDITION_NON_NULL(llvmModule);
	PRECONDITION_NON_NULL(semantics);

	this->llvmModule = llvmModule;
	this->enableDebug = enableDebug;
	resModule = std::make_shared<Module>(llvmModule, moduleName, semantics,
		config);
	variablesManager = std::make_shared<VariablesManager>(resModule);
	converter = LLVMValueConverter::create(resModule, variablesManager);
	structConverter = std::make_unique<StructureConverter>(basePass, converter, resModule);

	converter->setOptionStrictFPUSemantics(optionStrictFPUSemantics);

	convertAndAddFuncsDeclarations();
	convertAndAddGlobalVariables();
	convertFuncsBodies();
	makeIdentifiersValid();

	return resModule;
}

/**
* @brief Determines if given LLVM global variable @a var is external.
*/
bool LLVMIR2BIRConverter::isExternal(const llvm::GlobalVariable &var) const {
	// Only local linkage global variables (which are private and internal)
	// are internal. Others are external.
	return !var.hasLocalLinkage();
}

/**
* @brief Determines whether the given LLVM global variable @a globVar should be
*        converted and added into the resulting module.
*/
bool LLVMIR2BIRConverter::shouldBeConvertedAndAdded(
		const llvm::GlobalVariable &globVar) const {
	return !converter->storesStringLiteral(globVar);
}

/**
* @brief Converts the given LLVM global variable @a globVar into a variable in BIR.
*/
ShPtr<Variable> LLVMIR2BIRConverter::convertGlobalVariable(
		llvm::GlobalVariable &globVar) const {
	auto var = converter->convertValueToVariable(&globVar);
	if (isExternal(globVar)) {
		var->markAsExternal();
	}

	auto a = resModule->getConfig()->getAddressForGlobalVar(globVar.getName());
	var->setAddress(a);

	return var;
}

/**
* @brief Converts initializer of the given LLVM global variable @a globVar into
*        an expression in BIR.
*/
ShPtr<Expression> LLVMIR2BIRConverter::convertGlobalVariableInitializer(
		llvm::GlobalVariable &globVar) const {
	if (globVar.hasInitializer()) {
		return converter->convertConstantToExpression(
			globVar.getInitializer());
	}

	return nullptr;
}

/**
* @brief Converts all global variables of the input LLVM module and stores them
*        into the resulting module.
*/
void LLVMIR2BIRConverter::convertAndAddGlobalVariables() {
	if (enableDebug) {
		Log::phase("converting global variables", Log::SubPhase);
	}

	for (auto &globVar: llvmModule->globals()) {
		if (shouldBeConvertedAndAdded(globVar)) {
			auto variable = convertGlobalVariable(globVar);
			auto initializer = convertGlobalVariableInitializer(globVar);
			resModule->addGlobalVar(variable, initializer);
			variablesManager->addGlobalValVarPair(&globVar, variable);
		}
	}
}

/**
* @brief Converts parameters of the given LLVM function @a func into a list of
*        function parameters in BIR.
*/
VarVector LLVMIR2BIRConverter::convertFuncParams(llvm::Function &func) {
	VarVector params;
	for (auto &arg: func.args()) {
		params.push_back(converter->convertValueToVariable(&arg));
	}

	return params;
}

/**
* @brief Converts a declaration of the given LLVM function @a func into
*        a function declaration in BIR.
*/
ShPtr<Function> LLVMIR2BIRConverter::convertFuncDeclaration(
		llvm::Function &func) {
	// Clear local variables before conversion.
	variablesManager->reset();

	auto retType = converter->convertType(func.getReturnType());
	auto params = convertFuncParams(func);

	auto birFunc = Function::create(resModule, retType, func.getName(), params);
	variablesManager->addGlobalValVarPair(&func, birFunc->getAsVar());
	birFunc->setVarArg(func.isVarArg());
	return birFunc;
}

/**
* @brief Updates the given LLVM function @a func from declaration to definition.
*/
void LLVMIR2BIRConverter::updateFuncToDefinition(llvm::Function &func) {
	auto name = func.getName();
	if (enableDebug) {
		Log::phase("converting function " + name.str(), Log::SubPhase);
	}

	auto birFunc = resModule->getFuncByName(name);
	if (birFunc) {
		// Clear local variables before conversion.
		variablesManager->reset();

		birFunc->setParams(convertFuncParams(func));
		birFunc->setBody(structConverter->convertFuncBody(func));
		birFunc->setLocalVars(variablesManager->getLocalVars());

		generateVarDefinitions(birFunc);
	}
}

/**
* @brief Sorts local variables set @a vars alphabetically by name.
*/
VarVector LLVMIR2BIRConverter::sortLocalVars(const VarSet &vars) const {
	VarVector varVector(vars.begin(), vars.end());
	sortByName(varVector);
	return varVector;
}

/**
* @brief Generates variable definition statements at the beginning of @a func.
*/
void LLVMIR2BIRConverter::generateVarDefinitions(ShPtr<Function> func) const {
	auto vars = sortLocalVars(func->getLocalVars());
	for (auto i = vars.crbegin(), e = vars.crend(); i != e; ++i) {
		Address a = (*i)->getAddress();
		if (a.isUndefined()) a = func->getStartAddress();
		func->getBody()->prependStatement(
			VarDefStmt::create(*i, nullptr, nullptr, a));
	}
}

/**
* @brief Determines whether the given LLVM function @a func should be converted
*        and added into the resulting module.
*/
bool LLVMIR2BIRConverter::shouldBeConvertedAndAdded(
		const llvm::Function &func) const {
	// Do not convert 'available_externally' functions, because they have
	// definitions outside module.
	return !func.hasAvailableExternallyLinkage();
}

/**
* @brief Converts all functions declarations of the input LLVM module and stores
*        them into the resulting module.
*/
void LLVMIR2BIRConverter::convertAndAddFuncsDeclarations() {
	for (auto &func: llvmModule->functions()) {
		if (shouldBeConvertedAndAdded(func)) {
			resModule->addFunc(convertFuncDeclaration(func));
		}
	}
}

/**
* @brief Goes through all functions definitions of the input LLVM module and
*        converts their bodies and stores them into the resulting module.
*/
void LLVMIR2BIRConverter::convertFuncsBodies() {
	for (auto &func: llvmModule->functions()) {
		if (!func.isDeclaration() && shouldBeConvertedAndAdded(func)) {
			updateFuncToDefinition(func);
		}
	}
}

/**
* @brief Makes all identifiers valid by replacing invalid characters with valid
*        characters.
*/
void LLVMIR2BIRConverter::makeIdentifiersValid() {
	makeGlobVarsIdentifiersValid();
	makeFuncsIdentifiersValid();
}

/**
* @brief Makes all identifiers of the global variables valid.
*/
void LLVMIR2BIRConverter::makeGlobVarsIdentifiersValid() {
	for (auto &globVar: resModule->getGlobalVars()) {
		globVar->setName(makeIdentifierValid(globVar->getName()));
	}
}

/**
* @brief Makes all identifiers of the functions valid (function names, parameters
*        and local variables).
*/
void LLVMIR2BIRConverter::makeFuncsIdentifiersValid() {
	for (auto i = resModule->func_begin(), e = resModule->func_end(); i != e; ++i) {
		makeFuncIdentifiersValid(*i);
	}
}

/**
* @brief Makes all identifiers of the given function @a func valid (function
*        name, parameters and local variables).
*/
void LLVMIR2BIRConverter::makeFuncIdentifiersValid(ShPtr<Function> func) const {
	func->setName(makeIdentifierValid(func->getName()));
	makeFuncVariablesValid(func);
}

/**
* @brief Makes all identifiers of the local variables and parameters in the
*        given function @a func valid.
*/
void LLVMIR2BIRConverter::makeFuncVariablesValid(ShPtr<Function> func) const {
	for (auto &var: func->getLocalVars(true)) {
		var->setName(makeIdentifierValid(var->getName()));
	}
}

} // namespace llvmir2hll
} // namespace retdec
