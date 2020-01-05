/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter.h
* @brief A base class for all converters of LLVM IR to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_H

#include <string>

#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class Function;
class GlobalVariable;
class Module;
class Pass;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class Config;
class Expression;
class Function;
class LLVMValueConverter;
class Module;
class Semantics;
class StructureConverter;
class Variable;
class VariablesManager;

/**
* @brief A converter of LLVM IR to BIR.
*
* Instances of this class have reference object semantics.
*/
class LLVMIR2BIRConverter: private retdec::utils::NonCopyable {
public:
	static LLVMIR2BIRConverter* create(llvm::Pass *basePass);

	Module* convert(llvm::Module *llvmModule,
		const std::string &moduleName, Semantics* semantics,
		Config* config, bool enableDebug = false);

	/// @name Options
	/// @{
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

private:
	LLVMIR2BIRConverter(llvm::Pass *basePass);

	/// @name Global variables conversion
	/// @{
	bool isExternal(const llvm::GlobalVariable &var) const;
	bool shouldBeConvertedAndAdded(const llvm::GlobalVariable &globVar) const;
	Variable* convertGlobalVariable(llvm::GlobalVariable &globVar) const;
	Expression* convertGlobalVariableInitializer(
		llvm::GlobalVariable &globVar) const;
	void convertAndAddGlobalVariables();
	/// @}

	/// @name Functions conversion
	/// @{
	VarVector convertFuncParams(llvm::Function &func);
	Function* convertFuncDeclaration(llvm::Function &func);
	void updateFuncToDefinition(llvm::Function &func);
	VarVector sortLocalVars(const VarSet &vars) const;
	void generateVarDefinitions(Function* func) const;
	bool shouldBeConvertedAndAdded(const llvm::Function &func) const;
	void convertAndAddFuncsDeclarations();
	void convertFuncsBodies();
	/// @}

	/// @name Ensure that identifiers are valid
	/// @{
	void makeIdentifiersValid();
	void makeGlobVarsIdentifiersValid();
	void makeFuncsIdentifiersValid();
	void makeFuncIdentifiersValid(Function* func) const;
	void makeFuncVariablesValid(Function* func) const;
	/// @}

private:
	/// Pass that have instantiated the converter.
	llvm::Pass *basePass = nullptr;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;

	/// Should debugging messages be enabled?
	bool enableDebug;

	/// A converter from LLVM values to values in BIR.
	LLVMValueConverter* converter = nullptr;

	/// The input LLVM module.
	llvm::Module *llvmModule = nullptr;

	/// The resulting module in BIR.
	Module* resModule = nullptr;

	/// A converter of the LLVM function structure.
	StructureConverter* structConverter = nullptr;

	/// Variables manager.
	VariablesManager* variablesManager = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
