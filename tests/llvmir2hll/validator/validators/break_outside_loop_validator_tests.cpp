/**
* @file tests/llvmir2hll/validator/validators/break_outside_loop_validator_tests.cpp
* @brief Tests for the @c break_outside_loop_validator module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/validator/validators/break_outside_loop_validator.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c break_outside_loop_validator module.
*/
class BreakOutsideLoopValidatorTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		validator = BreakOutsideLoopValidator::create();
	}

protected:
	ShPtr<Validator> validator;
};

TEST_F(BreakOutsideLoopValidatorTests,
ValidatorHasNonEmptyID) {
	EXPECT_TRUE(!validator->getId().empty()) <<
		"the validator should have a non-empty ID";
}

TEST_F(BreakOutsideLoopValidatorTests,
OnDefaultModuleThereIsNoError) {
	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenBreakIsInsideWhileLoop) {
	// Set-up the module.
	//
	// def test():
	//     while True:
	//         break
	//
	ShPtr<WhileLoopStmt> whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), BreakStmt::create()));
	testFunc->setBody(whileLoop);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenBreakIsInsideForLoop) {
	// Set-up the module.
	//
	// def test():
	//     for i in range(0, 10):
	//         break
	//
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<ForLoopStmt> forLoopStmt(ForLoopStmt::create(
		varI, ConstInt::create(0, 16), LtOpExpr::create(varI, ConstInt::create(10, 16)),
		ConstInt::create(1, 16), BreakStmt::create()));
	testFunc->setBody(forLoopStmt);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenBreakIsInsideSwitch) {
	// Set-up the module.
	//
	// def test():
	//     switch 1:
	//         case 1:
	//             break
	//
	ShPtr<ConstInt> constInt1(ConstInt::create(1, 16));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(constInt1));
	switchStmt->addClause(constInt1, BreakStmt::create());
	testFunc->setBody(switchStmt);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenContinueIsInsideWhileLoop) {
	// Set-up the module.
	//
	// def test():
	//     while True:
	//         continue
	//
	ShPtr<WhileLoopStmt> whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), ContinueStmt::create()));
	testFunc->setBody(whileLoop);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenContinueIsInsideForLoop) {
	// Set-up the module.
	//
	// def test():
	//     for i in range(0, 10):
	//         continue
	//
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<ForLoopStmt> forLoopStmt(ForLoopStmt::create(
		varI, ConstInt::create(0, 16), LtOpExpr::create(varI, ConstInt::create(10, 16)),
		ConstInt::create(1, 16), ContinueStmt::create()));
	testFunc->setBody(forLoopStmt);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenBreakIsInsideIfInsideWhileLoop) {
	// Set-up the module.
	//
	// def test():
	//     while True:
	//         if 1:
	//             break
	//
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ConstInt::create(1, 16),
		BreakStmt::create()));
	ShPtr<WhileLoopStmt> whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), ifStmt));
	testFunc->setBody(whileLoop);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenContinueIsInsideIfInsideWhileLoop) {
	// Set-up the module.
	//
	// def test():
	//     while True:
	//         if 1:
	//             continue
	//
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ConstInt::create(1, 16),
		ContinueStmt::create()));
	ShPtr<WhileLoopStmt> whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), ifStmt));
	testFunc->setBody(whileLoop);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenBreakIsInsideIfInsideForLoop) {
	// Set-up the module.
	//
	// def test():
	//    for a in range(0, 10):
	//         if 1:
	//             break
	//
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ConstInt::create(1, 16),
		BreakStmt::create()));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<ForLoopStmt> forLoop(ForLoopStmt::create(
		varI, ConstInt::create(0, 16), LtOpExpr::create(varI, ConstInt::create(10, 16)),
		ConstInt::create(1, 16), ifStmt));
	testFunc->setBody(forLoop);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
NoErrorWhenContinueIsInsideIfInsideForLoop) {
	// Set-up the module.
	//
	// def test():
	//    for a in range(0, 10):
	//         if 1:
	//             continue
	//
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ConstInt::create(1, 16),
		ContinueStmt::create()));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<ForLoopStmt> forLoop(ForLoopStmt::create(
		varI, ConstInt::create(0, 16), LtOpExpr::create(varI, ConstInt::create(10, 16)),
		ConstInt::create(1, 16), ifStmt));
	testFunc->setBody(forLoop);

	EXPECT_TRUE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
ErrorWhenContinueIsInsideSwitch) {
	// Set-up the module.
	//
	// def test():
	//     switch 1:
	//         case 1:
	//             break
	//
	ShPtr<ConstInt> constInt1(ConstInt::create(1, 16));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(constInt1));
	switchStmt->addClause(constInt1, ContinueStmt::create());
	testFunc->setBody(switchStmt);

	EXPECT_FALSE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
ErrorWhenBreakIsDirectlyInFunctionBody) {
	// Set-up the module.
	//
	// def test():
	//     break
	//
	testFunc->setBody(BreakStmt::create());

	EXPECT_FALSE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
ErrorWhenContinueIsDirectlyInFunctionBody) {
	// Set-up the module.
	//
	// def test():
	//     continue
	//
	testFunc->setBody(ContinueStmt::create());

	EXPECT_FALSE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
ErrorWhenBreakIsInsideIfWithoutSurroundingLoop) {
	// Set-up the module.
	//
	// def test():
	//     if 1:
	//         break
	//
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ConstInt::create(1, 16),
		ContinueStmt::create()));
	testFunc->setBody(BreakStmt::create());

	EXPECT_FALSE(validator->validate(module));
}

TEST_F(BreakOutsideLoopValidatorTests,
ErrorWhenContinueIsInsideIfWithoutSurroundingLoop) {
	// Set-up the module.
	//
	// def test():
	//     if 1:
	//         continue
	//
	ShPtr<IfStmt> ifStmt(IfStmt::create(
		ConstInt::create(1, 16),
		ContinueStmt::create()));
	testFunc->setBody(ContinueStmt::create());

	EXPECT_FALSE(validator->validate(module));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
