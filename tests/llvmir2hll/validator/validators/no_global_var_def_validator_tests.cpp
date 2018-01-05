/**
* @file tests/llvmir2hll/validator/validators/no_global_var_def_validator_tests.cpp
* @brief Tests for the @c no_global_var_def_validator module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/validator/validators/no_global_var_def_validator.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c no_global_var_def_validator module.
*/
class NoGlobalVarDefValidatorTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		validator = NoGlobalVarDefValidator::create();
	}

protected:
	ShPtr<Validator> validator;
};

TEST_F(NoGlobalVarDefValidatorTests,
ValidatorHasNonEmptyID) {
	EXPECT_TRUE(!validator->getId().empty()) <<
		"the validator should have a non-empty ID";
}

TEST_F(NoGlobalVarDefValidatorTests,
OnDefaultModuleThereIsNoError) {
	EXPECT_TRUE(validator->validate(module));
}

TEST_F(NoGlobalVarDefValidatorTests,
NoErrorWhenThereIsAVariableDefiningStatementNotDefiningAGlobalVariable) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//     b = 1    (VarDefStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ConstInt::create(1, 16)));
	testFunc->setBody(varDefB);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(NoGlobalVarDefValidatorTests,
ErrorWhenThereIsAGlobalVariableDefiningStatement) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//     a = 1   (VarDefStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ConstInt::create(1, 16)));
	testFunc->setBody(varDefA);

	EXPECT_FALSE(validator->validate(module));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
