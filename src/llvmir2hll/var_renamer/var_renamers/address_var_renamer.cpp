/**
* @file src/llvmir2hll/var_renamer/var_renamers/address_var_renamer.cpp
* @brief Implementation of AddressVarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <cctype>

#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer_factory.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/address_var_renamer.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("address", ADDRESS_VAR_RENAMER_ID, VarRenamerFactory,
	AddressVarRenamer::create);

namespace {

/**
* @brief Generates a name for the given variable which includes its address (if
*        it can be extracted from the original variable's name).
*
* @par Preconditions
*  - both @a var and @a varNameGen are non-null
*/
std::string genVarNameWithAddressIfAvailable(ShPtr<Variable> var,
		VarNameGen *varNameGen) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(varNameGen);

	std::string address(getAddressFromName(var->getName(), ""));
	if (!address.empty()) {
		return varNameGen->getPrefix() + "_" + address;
	}
	return varNameGen->getNextVarName();
}

} // anonymous namespace

/**
* @brief Constructs a new renamer.
*
* For more details, see create().
*/
AddressVarRenamer::AddressVarRenamer(ShPtr<VarNameGen> varNameGen,
	bool useDebugNames): VarRenamer(varNameGen, useDebugNames),
		globalVarNameGen(NumVarNameGen::create("g")),
		paramVarNameGen(NumVarNameGen::create("a")),
		localVarNameGen(NumVarNameGen::create("v")) {}

/**
* @brief Creates a new renamer.
*
* @param[in] varNameGen Used generator of variable names.
* @param[in] useDebugNames Should we use variable names from debugging
*                          information?
*
* @par Preconditions
*  - @a varNameGen is non-null
*/
ShPtr<VarRenamer> AddressVarRenamer::create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames) {
	PRECONDITION_NON_NULL(varNameGen);

	return ShPtr<VarRenamer>(new AddressVarRenamer(varNameGen, useDebugNames));
}

std::string AddressVarRenamer::getId() const {
	return ADDRESS_VAR_RENAMER_ID;
}

void AddressVarRenamer::renameGlobalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genVarNameWithAddressIfAvailable(var,
		globalVarNameGen.get()));
}

void AddressVarRenamer::renameVarsInFunc(ShPtr<Function> func) {
	paramVarNameGen->restart();
	localVarNameGen->restart();

	VarRenamer::renameVarsInFunc(func);
}

void AddressVarRenamer::renameFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genVarNameWithAddressIfAvailable(var,
		paramVarNameGen.get()), func);
}

void AddressVarRenamer::renameFuncLocalVar(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genVarNameWithAddressIfAvailable(var,
		localVarNameGen.get()), func);
}

} // namespace llvmir2hll
} // namespace retdec
