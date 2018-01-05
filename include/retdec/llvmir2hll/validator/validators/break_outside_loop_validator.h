/**
* @file include/retdec/llvmir2hll/validator/validators/break_outside_loop_validator.h
* @brief A validator which checks that no break or continue statement appears
*        where it should not appear.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VALIDATOR_VALIDATORS_BREAK_OUTSIDE_LOOP_VALIDATOR_H
#define RETDEC_LLVMIR2HLL_VALIDATOR_VALIDATORS_BREAK_OUTSIDE_LOOP_VALIDATOR_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/validator/validator.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A validator which checks that no break or continue statement appears
*        where it should not appear.
*
* A break statement can appear only within a loop or a switch. A continue
* statement can appear only in a loop.
*
* Use create() to create instances. Instances of this class have reference
* object semantics.
*/
class BreakOutsideLoopValidator: public Validator {
public:
	virtual ~BreakOutsideLoopValidator() override;

	virtual std::string getId() const override;

	static ShPtr<Validator> create();

private:
	BreakOutsideLoopValidator();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<ContinueStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
