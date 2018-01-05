/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamers/hungarian_var_renamer.h
* @brief A renamer of variable names by using the Hungarian notation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_HUNGARIAN_VAR_RENAMER_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_HUNGARIAN_VAR_RENAMER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

namespace retdec {
namespace llvmir2hll {

class VarNameGen;

/**
* @brief A renamer of variable names by using the Hungarian notation.
*
* It names variables like UnifiedVarRenamer, but prefixes them by their type
* (like @c i_v1 for an integral local variable @c v1).
*
* List of supported types:
*  - @c i_ for IntType
*  - @c f_ for FloatType
*  - @c p_ for PointerType
*  - @c x_ for unsupported type
*
* Use create() to create instances.
*/
class HungarianVarRenamer: public VarRenamer {
public:
	static ShPtr<VarRenamer> create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	HungarianVarRenamer(ShPtr<VarNameGen> varNameGen, bool useDebugNames);

	virtual void renameGlobalVar(ShPtr<Variable> var) override;
	virtual void renameVarsInFunc(ShPtr<Function> func) override;
	virtual void renameFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) override;
	virtual void renameFuncLocalVar(ShPtr<Variable> var,
		ShPtr<Function> func) override;

private:
	/// Generator of names for global variables.
	UPtr<VarNameGen> globalVarNameGen;

	/// Generator of names for parameters.
	UPtr<VarNameGen> paramVarNameGen;

	/// Generator of names for local variables.
	UPtr<VarNameGen> localVarNameGen;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
