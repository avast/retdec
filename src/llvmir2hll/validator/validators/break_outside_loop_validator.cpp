/**
* @file src/llvmir2hll/validator/validators/break_outside_loop_validator.cpp
* @brief An implementation of the validator which checks that no break or
*        continue statement appears where it should not appear.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/validator/validator_factory.h"
#include "retdec/llvmir2hll/validator/validators/break_outside_loop_validator.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("BreakOutsideLoop", BREAK_OUTSIDE_LOOP_VALIDATOR_ID, ValidatorFactory,
	BreakOutsideLoopValidator::create);

/**
* @brief Constructs a new validator.
*/
BreakOutsideLoopValidator::BreakOutsideLoopValidator(): Validator() {}

/**
* @brief Destructs the validator.
*/
BreakOutsideLoopValidator::~BreakOutsideLoopValidator() {}

/**
* @brief Creates a new validator.
*/
ShPtr<Validator> BreakOutsideLoopValidator::create() {
	return ShPtr<BreakOutsideLoopValidator>(new BreakOutsideLoopValidator());
}

std::string BreakOutsideLoopValidator::getId() const {
	return BREAK_OUTSIDE_LOOP_VALIDATOR_ID;
}

void BreakOutsideLoopValidator::visit(ShPtr<BreakStmt> stmt) {
	// A break statement has to be inside of a loop or a switch statement. To
	// this end, get the innermost loop or switch.
	ShPtr<Statement> innLoopOrSwitch(getInnermostLoopOrSwitch(stmt));
	if (!innLoopOrSwitch) {
		validationError("In ", func->getName(), "(), found `", stmt,
			"` outside of a loop or a switch statement.");
	}
	OrderedAllVisitor::visit(stmt);
}

void BreakOutsideLoopValidator::visit(ShPtr<ContinueStmt> stmt) {
	// A continue statement has to be inside of a loop. To this end, get the
	// innermost loop.
	ShPtr<Statement> innLoop(getInnermostLoop(stmt));
	if (!innLoop) {
		validationError("In ", func->getName(), "(), found `", stmt,
			"` outside of a loop.");
	}
	OrderedAllVisitor::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
