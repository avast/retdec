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
	static ShPtr<VarRenamer> create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames = true);

	virtual std::string getId() const override;

private:
	AddressVarRenamer(ShPtr<VarNameGen> varNameGen, bool useDebugNames);

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
