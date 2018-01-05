/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamers/unified_var_renamer.h
* @brief A renamer of variable names which names the variables @c gX (global
*        variables), @c aX (parameters), and @c vX (local variables).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_UNIFIED_VAR_RENAMER_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_UNIFIED_VAR_RENAMER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

namespace retdec {
namespace llvmir2hll {

class VarNameGen;

/**
* @brief A renamer of variable names which names the variables @c gX
*        (global variables), @c aX (parameters), and @c vX (local variables).
*
* Use create() to create instances.
*/
class UnifiedVarRenamer: public VarRenamer {
public:
	static ShPtr<VarRenamer> create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	UnifiedVarRenamer(ShPtr<VarNameGen> varNameGen, bool useDebugNames);

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
