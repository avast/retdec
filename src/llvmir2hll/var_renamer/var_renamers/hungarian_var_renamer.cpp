/**
* @file src/llvmir2hll/var_renamer/var_renamers/hungarian_var_renamer.cpp
* @brief Implementation of HungarianVarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer_factory.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/hungarian_var_renamer.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("hungarian", HUNGARIAN_VAR_RENAMER_ID, VarRenamerFactory,
	HungarianVarRenamer::create);

namespace {

/**
* @brief Returns a proper prefix for the given variable by utilizing the
* Hungarian notation.
*
* For the list of supported types and their prefixes, see the class
* description.
*
* @par Preconditions
*  - @a var is non-null
*/
std::string getHungarianPrefix(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	ShPtr<Type> varType(var->getType());
	if (isa<IntType>(varType)) {
		return "i_";
	} else if (isa<FloatType>(varType)) {
		return "f_";
	} else if (isa<PointerType>(varType)) {
		return "p_";
	}
	// Unsupported type.
	return "x_";
}

/**
* @brief Generates a name for the given variable which includes a proper
*        Hungarian prefix.
*
* @par Preconditions
*  - both @a var and @a varNameGen are non-null
*/
std::string genVarNameWithHungarianPrefix(ShPtr<Variable> var,
		VarNameGen *varNameGen) {
	PRECONDITION_NON_NULL(var);
	PRECONDITION_NON_NULL(varNameGen);

	return getHungarianPrefix(var) + varNameGen->getNextVarName();
}

} // anonymous namespace

/**
* @brief Constructs a new renamer.
*
* For more details, see create().
*/
HungarianVarRenamer::HungarianVarRenamer(ShPtr<VarNameGen> varNameGen,
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
ShPtr<VarRenamer> HungarianVarRenamer::create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames) {
	PRECONDITION_NON_NULL(varNameGen);

	return ShPtr<VarRenamer>(new HungarianVarRenamer(varNameGen, useDebugNames));
}

std::string HungarianVarRenamer::getId() const {
	return HUNGARIAN_VAR_RENAMER_ID;
}

void HungarianVarRenamer::renameGlobalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genVarNameWithHungarianPrefix(var,
		globalVarNameGen.get()));
}

void HungarianVarRenamer::renameVarsInFunc(ShPtr<Function> func) {
	paramVarNameGen->restart();
	localVarNameGen->restart();

	VarRenamer::renameVarsInFunc(func);
}

void HungarianVarRenamer::renameFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genVarNameWithHungarianPrefix(var,
		paramVarNameGen.get()), func);
}

void HungarianVarRenamer::renameFuncLocalVar(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genVarNameWithHungarianPrefix(var,
		localVarNameGen.get()), func);
}

} // namespace llvmir2hll
} // namespace retdec
