/**
* @file include/llvmir2hll/validator/validators/no_global_var_def_validator.h
* @brief A validator which checks that no global variable is defined in a
*        VarDefStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_VALIDATOR_VALIDATORS_NO_GLOBAL_VAR_DEF_VALIDATOR_H
#define LLVMIR2HLL_VALIDATOR_VALIDATORS_NO_GLOBAL_VAR_DEF_VALIDATOR_H

#include <string>

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/validator/validator.h"

namespace llvmir2hll {

/**
* @brief A validator which checks that no global variable is defined in a
*        VarDefStmt.
*
* A global variable has to be defined in a module, i.e. on the global level. A
* VarDefStmt in a function, where the left-hand side is a global variable, is
* invalid. This validator finds such variable-defining statements.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class NoGlobalVarDefValidator: public Validator {
public:
	virtual ~NoGlobalVarDefValidator() override;

	virtual std::string getId() const override;

	static ShPtr<Validator> create();

private:
	NoGlobalVarDefValidator();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll

#endif
