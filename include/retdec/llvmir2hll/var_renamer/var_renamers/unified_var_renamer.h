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
	static VarRenamer* create(VarNameGen* varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	UnifiedVarRenamer(VarNameGen* varNameGen, bool useDebugNames);

	virtual void renameGlobalVar(Variable* var) override;
	virtual void renameVarsInFunc(Function* func) override;
	virtual void renameFuncParam(Variable* var,
		Function* func) override;
	virtual void renameFuncLocalVar(Variable* var,
		Function* func) override;

private:
	/// Generator of names for global variables.
	VarNameGen* globalVarNameGen = nullptr;

	/// Generator of names for parameters.
	VarNameGen* paramVarNameGen = nullptr;

	/// Generator of names for local variables.
	VarNameGen* localVarNameGen = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
