/**
* @file src/llvmir2hll/validator/validators/return_validator.cpp
* @brief An implementation of the validator which checks returns from
*        functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/validator/validator_factory.h"
#include "retdec/llvmir2hll/validator/validators/return_validator.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("Return", RETURN_VALIDATOR_ID, ValidatorFactory,
	ReturnValidator::create);

/**
* @brief Constructs a new validator.
*/
ReturnValidator::ReturnValidator(): Validator() {}

/**
* @brief Destructs the validator.
*/
ReturnValidator::~ReturnValidator() {}

/**
* @brief Creates a new validator.
*/
ShPtr<Validator> ReturnValidator::create() {
	return ShPtr<ReturnValidator>(new ReturnValidator());
}

std::string ReturnValidator::getId() const {
	return RETURN_VALIDATOR_ID;
}

void ReturnValidator::visit(ShPtr<ReturnStmt> stmt) {
	// If the function is non-void, there has to be a return value.
	if (!isa<VoidType>(func->getRetType()) && !stmt->getRetVal()) {
		validationError("In ", func->getName(), "(), which is non-void, ",
			"found a ReturnStmt `", stmt, "` without a return value.");
	}

	// If the function is void, there cannot be a return value.
	if (isa<VoidType>(func->getRetType()) && stmt->getRetVal()) {
		validationError("In ", func->getName(), "(), which returns void, ",
			"found a ReturnStmt `", stmt, "` with a return value.");
	}

	OrderedAllVisitor::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
