/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamers/address_var_renamer.h
* @brief A renamer of variable names which extracts and uses the original
*        addresses of the variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_ADDRESS_VAR_RENAMER_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMERS_ADDRESS_VAR_RENAMER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

namespace retdec {
namespace llvmir2hll {

class VarNameGen;

/**
* @brief A renamer of variable names which extracts and uses the original
*        addresses of the variables.
*
* It names variables by extracting their address from their original name. For
* example, the local variable @c %u2_804839f1 is named @c v_804839f1 (the used
* prefix corresponds to the naming convention of UnifiedVarRenamer).
*
* If there is no address in the original name of the variable, we name it by
* using the naming convention of UnifiedVarRenamer.
*
* Use create() to create instances.
*/
class AddressVarRenamer: public VarRenamer {
public:
	static VarRenamer* create(VarNameGen* varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	AddressVarRenamer(VarNameGen* varNameGen, bool useDebugNames);

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
