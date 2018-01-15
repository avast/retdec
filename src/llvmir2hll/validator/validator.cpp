/**
* @file src/llvmir2hll/validator/validator.cpp
* @brief Implementation of Validator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/validator/validator.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new validator.
*/
Validator::Validator(): module(), func(), moduleIsCorrect(true) {}

/**
* @brief Destructs the validator.
*/
Validator::~Validator() {}

/**
* @brief Validates the given module.
*
* @param[in] module Module to be validated.
* @param[in] printMessageOnError If @c true and the module is not valid, it
*                                prints a warning message to standard error.
*
* @return @c true if the module is correct, @c false otherwise.
*
* The details depend on the concrete validator. See its class description. If
* there are multiple errors and @a printMessageOnError is @c true, it prints a
* warning message for each of these errors.
*
* @par Preconditions
*  - @a module is non-null
*/
bool Validator::validate(ShPtr<Module> module, bool printMessageOnError) {
	PRECONDITION_NON_NULL(module);

	this->module = module;
	this->printMessageOnError = printMessageOnError;
	this->moduleIsCorrect = true;

	runValidation();

	return moduleIsCorrect;
}

/**
* @brief Traverses all global variables in the current module and calls @c
*        accept() on every one of them.
*/
void Validator::traverseAllGlobalVariables() {
	for (auto i = module->global_var_begin(),
			e = module->global_var_end(); i != e; ++i) {
		(*i)->accept(this);
	}
}

/**
* @brief Traverses all functions in the current module and calls @c accept() on
*        every one of them.
*
* Furthermore, before traversing a function, it sets the data member @c func to
* the traversed function.
*/
void Validator::traverseAllFunctions() {
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		func = *i;
		func->accept(this);
	}
}

/**
* @brief Runs the validation over the module.
*
* By default, this function calls traverseAllGlobalVariables() and
* traverseAllFunctions(). If you want to do anything else, redefine this member
* function.
*/
void Validator::runValidation() {
	traverseAllGlobalVariables();
	traverseAllFunctions();
}

} // namespace llvmir2hll
} // namespace retdec
