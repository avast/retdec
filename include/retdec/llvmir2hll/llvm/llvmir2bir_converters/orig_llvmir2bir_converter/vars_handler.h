/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/vars_handler.h
* @brief Handling of variables created during decompilation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_VARS_HANDLER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_VARS_HANDLER_H

#include <map>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class Type;
class Value;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class Module;
class Variable;

/**
* @brief Handler of variables created during decompilation.
*
* Instances of this class have reference object semantics. This class is not
* meant to be subclassed.
*/
class VarsHandler final: private retdec::utils::NonCopyable {
public:
	VarsHandler(ShPtr<Module> resModule, ShPtr<VarNameGen> varNameGen);
	~VarsHandler();

	void startConvertingGlobalVars();
	void stopConvertingGlobalVars();
	void reset();

	ShPtr<Variable> getVariableByName(const std::string &varName);
	std::string getValueName(const llvm::Value *v);

	void addLocalVar(ShPtr<Variable> var);
	bool localVarExists(const std::string &varName) const;
	VarSet getLocalVars() const;

	void addAllocatedVarType(llvm::Value *var, llvm::Type *varType);
	llvm::Type *getAllocatedVarType(llvm::Value *var) const;

private:
	/// Mapping of a string into a variable.
	using StringVarMap = std::map<std::string, ShPtr<Variable>>;

private:
	/// The resulting module in our IR.
	ShPtr<Module> resModule;

	/// Variable names generator.
	ShPtr<VarNameGen> varNameGen;

	/// Naming of unnamed local variables.
	std::map<const llvm::Value *, std::string> anonVarNames;

	/// Mapping between a local variable's name and the actual variable (or
	/// the null pointer if the variable hasn't been defined yet). Function
	/// parameters are also included.
	StringVarMap localVars;

	/// Mapping between a local variable allocated by an alloca instruction
	/// and its type.
	std::map<llvm::Value *, llvm::Type *> allocatedVarTypes;

	/// Are we converting global variables?
	bool convertingGlobalVars;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
