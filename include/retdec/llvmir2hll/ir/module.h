/**
* @file include/retdec/llvmir2hll/ir/module.h
* @brief A representation of a complete module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_MODULE_H
#define RETDEC_LLVMIR2HLL_IR_MODULE_H

#include <cstddef>
#include <functional>
#include <map>
#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/filter_iterator.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class Module;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class Config;
class Expression;
class Function;
class GlobalVarDef;
class Semantics;
class Variable;

/**
* @brief A representation of a complete module.
*
* Instances of this class have reference object semantics. This class is not
* meant to be subclassed.
*/
class Module final: private retdec::utils::NonCopyable {
public:
	/// Global variable iterator.
	using global_var_iterator = GlobalVarDefVector::const_iterator;

	/// Function iterator.
	using func_iterator = FuncVector::const_iterator;

	/// Iterator over filtered functions (definitions, declarations, etc.).
	using func_filter_iterator = retdec::utils::FilterIterator<func_iterator>;

public:
	Module(const llvm::Module *llvmModule, const std::string &identifier,
		ShPtr<Semantics> semantics, ShPtr<Config> config);

	~Module();

	const llvm::Module *getLLVMModule() const;
	std::string getIdentifier(bool stripDirs = true) const;
	ShPtr<Semantics> getSemantics() const;

	/// @name Global Variables Accessors
	/// @{
	void addGlobalVar(ShPtr<Variable> var, ShPtr<Expression> init = nullptr);
	void removeGlobalVar(ShPtr<Variable> var);
	bool isGlobalVar(ShPtr<Variable> var) const;
	bool isGlobalVarStoringStringLiteral(const std::string &varName) const;
	ShPtr<Expression> getInitForGlobalVar(ShPtr<Variable> var) const;
	ShPtr<Variable> getGlobalVarByName(const std::string &varName) const;
	bool hasGlobalVars() const;
	bool hasGlobalVar(const std::string &name) const;
	VarSet getGlobalVars() const;
	VarSet getExternalGlobalVars() const;
	std::string getRegisterForGlobalVar(ShPtr<Variable> var) const;
	std::string getDetectedCryptoPatternForGlobalVar(ShPtr<Variable> var) const;

	global_var_iterator global_var_begin() const;
	global_var_iterator global_var_end() const;
	/// @}

	/// @name Functions Accessors
	/// @{
	void addFunc(ShPtr<Function> func);
	void removeFunc(ShPtr<Function> func);
	bool funcExists(ShPtr<Function> func) const;
	ShPtr<Function> getFuncByName(const std::string &funcName) const;
	bool hasFuncWithName(const std::string &funcName) const;
	bool correspondsToFunc(ShPtr<Variable> var) const;
	bool hasMainFunc() const;
	bool isMainFunc(ShPtr<Function> func) const;
	VarSet getVarsForFuncs() const;
	std::size_t getNumOfFuncDefinitions() const;
	bool hasFuncDefinitions() const;

	bool hasUserDefinedFuncs() const;
	FuncSet getUserDefinedFuncs() const;

	bool hasStaticallyLinkedFuncs() const;
	FuncSet getStaticallyLinkedFuncs() const;
	void markFuncAsStaticallyLinked(ShPtr<Function> func);

	bool hasDynamicallyLinkedFuncs() const;
	FuncSet getDynamicallyLinkedFuncs() const;

	bool hasSyscallFuncs() const;
	FuncSet getSyscallFuncs() const;

	bool hasInstructionIdiomFuncs() const;
	FuncSet getInstructionIdiomFuncs() const;

	bool isExportedFunc(ShPtr<Function> func) const;

	std::string getRealNameForFunc(ShPtr<Function> func) const;
	std::string getDeclarationStringForFunc(ShPtr<Function> func) const;
	std::string getCommentForFunc(ShPtr<Function> func) const;
	StringSet getDetectedCryptoPatternsForFunc(ShPtr<Function> func) const;
	std::string getWrappedFuncName(ShPtr<Function> func) const;
	std::string getDemangledNameOfFunc(ShPtr<Function> func) const;

	StringSet getNamesOfFuncsFixedWithLLVMIRFixer() const;

	AddressRange getAddressRangeForFunc(ShPtr<Function> func) const;
	bool hasAddressRange(ShPtr<Function> func) const;
	bool allFuncDefinitionsHaveAddressRange() const;

	LineRange getLineRangeForFunc(ShPtr<Function> func) const;
	bool hasLineRange(ShPtr<Function> func) const;
	bool allFuncDefinitionsHaveLineRange() const;

	func_iterator func_begin() const;
	func_iterator func_end() const;

	func_filter_iterator func_definition_begin() const;
	func_filter_iterator func_definition_end() const;

	func_filter_iterator func_declaration_begin() const;
	func_filter_iterator func_declaration_end() const;
	/// @}

	/// @name Local Variables Accessors
	/// @{
	std::string comesFromGlobalVar(ShPtr<Function> func, ShPtr<Variable> var) const;
	/// @}

	/// @name Classes Accessors
	/// @{
	bool hasClasses() const;
	StringSet getClassNames() const;
	std::string getClassForFunc(ShPtr<Function> func) const;
	std::string getTypeOfFuncInClass(ShPtr<Function> func,
		const std::string &cl) const;
	StringVector getBaseClassNames(const std::string &cl) const;
	std::string getDemangledNameOfClass(const std::string &cl) const;
	/// @}

	/// @name Debug Info Accessors
	/// @{
	bool isDebugInfoAvailable() const;

	std::string getDebugModuleNameForFunc(ShPtr<Function> func) const;
	bool hasAssignedDebugModuleName(ShPtr<Function> func) const;
	StringSet getDebugModuleNames() const;

	std::string getDebugNameForGlobalVar(ShPtr<Variable> var) const;
	std::string getDebugNameForLocalVar(ShPtr<Function> func,
		ShPtr<Variable> var) const;

	std::string getDebugNameForVar(ShPtr<Variable> var) const;
	bool hasAssignedDebugName(ShPtr<Variable> var) const;
	void addDebugNameForVar(ShPtr<Variable> var, const std::string &name);
	/// @}

	/// @name Meta Information
	/// @{
	std::string getFrontendRelease() const;
	std::size_t getNumberOfFuncsDetectedInFrontend() const;
	std::string getDetectedCompilerOrPacker() const;
	std::string getDetectedLanguage() const;
	StringSet getSelectedButNotFoundFuncs() const;
	/// @}

private:
	/// Mapping of a function into an address range.
	using FuncAddressRangeMap = std::map<ShPtr<Function>, AddressRange>;

private:
	/// Original module from which this module has been created.
	const llvm::Module *llvmModule;

	/// Identifier of the module.
	std::string identifier;

	/// The used semantics.
	ShPtr<Semantics> semantics;

	/// The used config.
	ShPtr<Config> config;

	/// Global variables.
	GlobalVarDefVector globalVars;

	/// Functions.
	FuncVector funcs;

	/// Mapping of a variable into its name in the debug information.
	VarStringMap debugVarNameMap;

private:
	bool hasFuncSatisfyingPredicate(
		std::function<bool (ShPtr<Function>)> pred
	) const;
	FuncSet getFuncsSatisfyingPredicate(
		std::function<bool (ShPtr<Function>)> pred
	) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
