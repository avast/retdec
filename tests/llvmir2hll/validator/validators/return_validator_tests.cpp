/**
* @file tests/llvmir2hll/validator/validators/return_validator_tests.cpp
* @brief Tests for the @c return_validator module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/validator/validators/return_validator.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c return_validator module.
*/
class ReturnValidatorTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		validator = ReturnValidator::create();
	}

protected:
	ShPtr<Validator> validator;
};

TEST_F(ReturnValidatorTests,
ValidatorHasNonEmptyID) {
	EXPECT_TRUE(!validator->getId().empty()) <<
		"the validator should have a non-empty ID";
}

TEST_F(ReturnValidatorTests,
OnDefaultModuleThereIsNoError) {
	EXPECT_TRUE(validator->validate(module));
}

TEST_F(ReturnValidatorTests,
NoErrorOnVoidWithReturnNothing) {
	// Set-up the module.
	//
	// void test() {
	//    return;
	// }
	//
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	testFunc->setBody(returnStmt);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(ReturnValidatorTests,
NoErrorOnNonVoidWithReturnValue) {
	// Set-up the module.
	//
	// int test2() {
	//    return 1;
	// }
	//
	ShPtr<Function> testFunc2 = FunctionBuilder("test2")
		.definitionWithBody(ReturnStmt::create(ConstInt::create(1, 16)))
		.withRetType(IntType::create(32))
		.build();
	module->addFunc(testFunc2);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(ReturnValidatorTests,
ErrorOnVoidWithReturnValue) {
	// Set-up the module.
	//
	// void test() {
	//    return 1;
	// }
	//
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(ConstInt::create(1, 16)));
	testFunc->setBody(returnStmt);

	EXPECT_FALSE(validator->validate(module));
}

TEST_F(ReturnValidatorTests,
ErrorOnNonVoidWithoutReturnValue) {
	// Set-up the module.
	//
	// int test2() {
	//    return;
	// }
	//
	ShPtr<Function> testFunc2 = FunctionBuilder("test2")
		.definitionWithBody(ReturnStmt::create())
		.withRetType(IntType::create(32))
		.build();
	module->addFunc(testFunc2);

	EXPECT_FALSE(validator->validate(module));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
