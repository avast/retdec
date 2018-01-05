/**
* @file src/llvmir2hll/var_renamer/var_renamers/unified_var_renamer.cpp
* @brief Implementation of UnifiedVarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer_factory.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/unified_var_renamer.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("unified", UNIFIED_VAR_RENAMER_ID, VarRenamerFactory,
	UnifiedVarRenamer::create);

/**
* @brief Constructs a new renamer.
*
* For more details, see create().
*/
UnifiedVarRenamer::UnifiedVarRenamer(ShPtr<VarNameGen> varNameGen,
	bool useDebugNames): VarRenamer(varNameGen, useDebugNames),
		globalVarNameGen(NumVarNameGen::create("g")),
		paramVarNameGen(NumVarNameGen::create("a")),
		localVarNameGen(NumVarNameGen::create("v")) {}

/**
* @brief Creates a new renamer.
*
* @param[in] varNameGen Used generator of variable names (not used in this
*                       renamer).
* @param[in] useDebugNames Should we use variable names from debugging
*                          information?
*
* @par Preconditions
*  - @a varNameGen is non-null
*/
ShPtr<VarRenamer> UnifiedVarRenamer::create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames) {
	PRECONDITION_NON_NULL(varNameGen);

	return ShPtr<VarRenamer>(new UnifiedVarRenamer(varNameGen, useDebugNames));
}

std::string UnifiedVarRenamer::getId() const {
	return UNIFIED_VAR_RENAMER_ID;
}

void UnifiedVarRenamer::renameGlobalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	assignName(var, globalVarNameGen->getNextVarName());
}

void UnifiedVarRenamer::renameVarsInFunc(ShPtr<Function> func) {
	paramVarNameGen->restart();
	localVarNameGen->restart();

	VarRenamer::renameVarsInFunc(func);
}

void UnifiedVarRenamer::renameFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, paramVarNameGen->getNextVarName(), func);
}

void UnifiedVarRenamer::renameFuncLocalVar(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, localVarNameGen->getNextVarName(), func);
}

} // namespace llvmir2hll
} // namespace retdec
