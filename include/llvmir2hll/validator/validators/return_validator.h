/**
* @file include/llvmir2hll/validator/validators/return_validator.h
* @brief A validator which checks returns from functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_VALIDATOR_VALIDATORS_RETURN_VALIDATOR_H
#define LLVMIR2HLL_VALIDATOR_VALIDATORS_RETURN_VALIDATOR_H

#include <string>

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/validator/validator.h"

namespace llvmir2hll {

/**
* @brief A validator which checks returns from functions.
*
* Currently, the following checks are done:
*  - if the function returns void, a return statement cannot return a value
*  - if the function is non-void, a return statement has to return a value
*
* Use create() to create instances. Instances of this class have reference
* object semantics.
*/
class ReturnValidator: public Validator {
public:
	virtual ~ReturnValidator() override;

	virtual std::string getId() const override;

	static ShPtr<Validator> create();

private:
	ReturnValidator();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll

#endif
