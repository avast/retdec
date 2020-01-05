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
		Semantics* semantics, Config* config);

	const llvm::Module *getLLVMModule() const;
	std::string getIdentifier(bool stripDirs = true) const;
	Semantics* getSemantics() const;
	Config* getConfig() const;

	/// @name Global Variables Accessors
	/// @{
	void addGlobalVar(Variable* var, Expression* init = nullptr);
	void removeGlobalVar(Variable* var);
	bool isGlobalVar(Variable* var) const;
	bool isGlobalVarStoringStringLiteral(const std::string &varName) const;
	Expression* getInitForGlobalVar(Variable* var) const;
	Variable* getGlobalVarByName(const std::string &varName) const;
	bool hasGlobalVars() const;
	bool hasGlobalVar(const std::string &name) const;
	VarSet getGlobalVars() const;
	VarSet getExternalGlobalVars() const;
	std::string getRegisterForGlobalVar(Variable* var) const;
	std::string getDetectedCryptoPatternForGlobalVar(Variable* var) const;

	global_var_iterator global_var_begin() const;
	global_var_iterator global_var_end() const;
	/// @}

	/// @name Functions Accessors
	/// @{
	void addFunc(Function* func);
	void removeFunc(Function* func);
	bool funcExists(Function* func) const;
	Function* getFuncByName(const std::string &funcName) const;
	bool hasFuncWithName(const std::string &funcName) const;
	bool correspondsToFunc(Variable* var) const;
	bool hasMainFunc() const;
	bool isMainFunc(Function* func) const;
	VarSet getVarsForFuncs() const;
	std::size_t getNumOfFuncDefinitions() const;
	bool hasFuncDefinitions() const;

	bool hasUserDefinedFuncs() const;
	FuncSet getUserDefinedFuncs() const;

	bool hasStaticallyLinkedFuncs() const;
	FuncSet getStaticallyLinkedFuncs() const;
	void markFuncAsStaticallyLinked(Function* func);

	bool hasDynamicallyLinkedFuncs() const;
	FuncSet getDynamicallyLinkedFuncs() const;

	bool hasSyscallFuncs() const;
	FuncSet getSyscallFuncs() const;

	bool hasInstructionIdiomFuncs() const;
	FuncSet getInstructionIdiomFuncs() const;

	bool isExportedFunc(Function* func) const;

	std::string getRealNameForFunc(Function* func) const;
	std::string getDeclarationStringForFunc(Function* func) const;
	std::string getCommentForFunc(Function* func) const;
	StringSet getDetectedCryptoPatternsForFunc(Function* func) const;
	std::string getWrappedFuncName(Function* func) const;
	std::string getDemangledNameOfFunc(Function* func) const;

	AddressRange getAddressRangeForFunc(const Function* func) const;
	bool hasAddressRange(Function* func) const;
	bool allFuncDefinitionsHaveAddressRange() const;

	LineRange getLineRangeForFunc(Function* func) const;
	bool hasLineRange(Function* func) const;
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
	std::string comesFromGlobalVar(Function* func, Variable* var) const;
	/// @}

	/// @name Classes Accessors
	/// @{
	bool hasClasses() const;
	StringSet getClassNames() const;
	std::string getClassForFunc(Function* func) const;
	std::string getTypeOfFuncInClass(Function* func,
		const std::string &cl) const;
	StringVector getBaseClassNames(const std::string &cl) const;
	std::string getDemangledNameOfClass(const std::string &cl) const;
	/// @}

	/// @name Debug Info Accessors
	/// @{
	bool isDebugInfoAvailable() const;

	std::string getDebugModuleNameForFunc(Function* func) const;
	bool hasAssignedDebugModuleName(Function* func) const;
	StringSet getDebugModuleNames() const;

	std::string getDebugNameForGlobalVar(Variable* var) const;
	std::string getDebugNameForLocalVar(Function* func,
		Variable* var) const;

	std::string getDebugNameForVar(Variable* var) const;
	bool hasAssignedDebugName(Variable* var) const;
	void addDebugNameForVar(Variable* var, const std::string &name);
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
	using FuncAddressRangeMap = std::map<Function*, AddressRange>;

private:
	/// Original module from which this module has been created.
	const llvm::Module *llvmModule = nullptr;

	/// Identifier of the module.
	std::string identifier;

	/// The used semantics.
	Semantics* semantics = nullptr;

	/// The used config.
	Config* config = nullptr;

	/// Global variables.
	GlobalVarDefVector globalVars;

	/// Functions.
	FuncVector funcs;

	/// Mapping of a variable into its name in the debug information.
	VarStringMap debugVarNameMap;

private:
	bool hasFuncSatisfyingPredicate(
		std::function<bool (Function*)> pred
	) const;
	FuncSet getFuncsSatisfyingPredicate(
		std::function<bool (Function*)> pred
	) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
