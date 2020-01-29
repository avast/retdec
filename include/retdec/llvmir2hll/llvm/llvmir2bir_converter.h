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
	static ShPtr<LLVMIR2BIRConverter> create(llvm::Pass *basePass);

	ShPtr<Module> convert(llvm::Module *llvmModule,
		const std::string &moduleName, ShPtr<Semantics> semantics,
		ShPtr<Config> config, bool enableDebug = false);

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
	ShPtr<Variable> convertGlobalVariable(llvm::GlobalVariable &globVar) const;
	ShPtr<Expression> convertGlobalVariableInitializer(
		llvm::GlobalVariable &globVar) const;
	void convertAndAddGlobalVariables();
	/// @}

	/// @name Functions conversion
	/// @{
	VarVector convertFuncParams(llvm::Function &func);
	ShPtr<Function> convertFuncDeclaration(llvm::Function &func);
	void updateFuncToDefinition(llvm::Function &func);
	VarVector sortLocalVars(const VarSet &vars) const;
	void generateVarDefinitions(ShPtr<Function> func) const;
	bool shouldBeConvertedAndAdded(const llvm::Function &func) const;
	void convertAndAddFuncsDeclarations();
	void convertFuncsBodies();
	/// @}

	/// @name Ensure that identifiers are valid
	/// @{
	void makeIdentifiersValid();
	void makeGlobVarsIdentifiersValid();
	void makeFuncsIdentifiersValid();
	void makeFuncIdentifiersValid(ShPtr<Function> func) const;
	void makeFuncVariablesValid(ShPtr<Function> func) const;
	/// @}

private:
	/// Pass that have instantiated the converter.
	llvm::Pass *basePass;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;

	/// Should debugging messages be enabled?
	bool enableDebug;

	/// A converter from LLVM values to values in BIR.
	ShPtr<LLVMValueConverter> converter;

	/// The input LLVM module.
	llvm::Module *llvmModule;

	/// The resulting module in BIR.
	ShPtr<Module> resModule;

	/// A converter of the LLVM function structure.
	UPtr<StructureConverter> structConverter;

	/// Variables manager.
	ShPtr<VariablesManager> variablesManager;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
