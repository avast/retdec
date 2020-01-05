/**
* @file src/llvmir2hll/var_renamer/var_renamers/simple_var_renamer.cpp
* @brief Implementation of SimpleVarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer_factory.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/simple_var_renamer.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("simple", SIMPLE_VAR_RENAMER_ID, VarRenamerFactory,
	SimpleVarRenamer::create);

/**
* @brief Constructs a new renamer.
*
* For more details, see create().
*/
SimpleVarRenamer::SimpleVarRenamer(VarNameGen* varNameGen,
	bool useDebugNames): VarRenamer(varNameGen, useDebugNames) {}

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
VarRenamer* SimpleVarRenamer::create(VarNameGen* varNameGen,
		bool useDebugNames) {
	PRECONDITION_NON_NULL(varNameGen);

	return new SimpleVarRenamer(varNameGen, useDebugNames);
}

std::string SimpleVarRenamer::getId() const {
	return SIMPLE_VAR_RENAMER_ID;
}

} // namespace llvmir2hll
} // namespace retdec
