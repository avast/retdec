/**
* @file src/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.cpp
* @brief Implementation of NumVarNameGen.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/StringExtras.h>

#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen_factory.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("num", NUM_VAR_NAME_GEN_ID, VarNameGenFactory,
	NumVarNameGen::create);

namespace {
/// Default number for the first variable name.
const unsigned FIRST_VAR_NUM = 1;
}

/**
* @brief Constructs a new NumVarNameGen object.
*
* For more details, see create().
*/
NumVarNameGen::NumVarNameGen(std::string prefix):
		VarNameGen(prefix), nextVarNum(FIRST_VAR_NUM) {}

/**
* @brief Creates a new NumVarNameGen object.
*
* @param[in] prefix Prefix of all returned variable names.
*
* The getNextVarName() function then returns variable names of the form @c
* prefixN, where N is a number.
*/
UPtr<VarNameGen> NumVarNameGen::create(std::string prefix) {
	return UPtr<VarNameGen>(new NumVarNameGen(prefix));
}

std::string NumVarNameGen::getId() const {
	return NUM_VAR_NAME_GEN_ID;
}

void NumVarNameGen::restart() {
	nextVarNum = FIRST_VAR_NUM;
}

std::string NumVarNameGen::getNextVarName() {
	if (nextVarNum + 1 == 0) {
		// No more available numbers, so restart the generator. Note that this
		// check is perfectly safe because UINT_MAX + 1 == 0 is guaranteed by
		// the standard.
		restart();
		return getNextVarName();
	} else {
		return prefix + llvm::utostr(nextVarNum++);
	}
}

} // namespace llvmir2hll
} // namespace retdec
