/**
* @file src/llvmir2hll/validator/validators/no_global_var_def_validator.cpp
* @brief Implementation of NoGlobalVarDefValidator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/validator/validator_factory.h"
#include "retdec/llvmir2hll/validator/validators/no_global_var_def_validator.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("NoGlobalVarDef", NO_GLOBAL_VAR_DEF_VALIDATOR_ID, ValidatorFactory,
	NoGlobalVarDefValidator::create);

/**
* @brief Constructs a new validator.
*/
NoGlobalVarDefValidator::NoGlobalVarDefValidator(): Validator() {}

/**
* @brief Destructs the validator.
*/
NoGlobalVarDefValidator::~NoGlobalVarDefValidator() {}

/**
* @brief Creates a new validator.
*/
ShPtr<Validator> NoGlobalVarDefValidator::create() {
	return ShPtr<NoGlobalVarDefValidator>(new NoGlobalVarDefValidator());
}

std::string NoGlobalVarDefValidator::getId() const {
	return NO_GLOBAL_VAR_DEF_VALIDATOR_ID;
}

void NoGlobalVarDefValidator::visit(ShPtr<VarDefStmt> stmt) {
	// The left-hand side of a VarDefStmt cannot be a global variable.
	if (module->isGlobalVar(stmt->getVar())) {
		validationError("In ", func->getName(), "(), found a VarDefStmt `",
			stmt, "` that defines a global variable.");
	}
	OrderedAllVisitor::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
