/**
* @file tests/llvmir2hll/hll/bracket_managers/no_bracket_manager_tests.cpp
* @brief Tests for the @c no_bracket_manager module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/hll/bracket_managers/no_bracket_manager.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c no_bracket_manager module.
*/
class NoBracketManagerTests: public TestsWithModule {};

TEST_F(NoBracketManagerTests,
ManagerHasNonEmptyID) {
	NoBracketManager noBrackets(module);

	EXPECT_TRUE(!noBrackets.getId().empty()) <<
		"the manager should have a non-empty ID";
}

TEST_F(NoBracketManagerTests,
MulAdd) {
	// return 2 * (0 + a);
	//
	// expected output: return (2 * (0 + a));
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			ConstInt::create(0, 64),
			varA
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			ConstInt::create(2,64),
			addOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	NoBracketManager noBracketManager(module);

	EXPECT_TRUE(noBracketManager.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
	EXPECT_TRUE(noBracketManager.areBracketsNeeded(mulOpExpr)) <<
		"expected brackets around " << mulOpExpr;
}

TEST_F(NoBracketManagerTests,
MulDivMul) {
	// return a * ((b / c) * 3);
	//
	// expected output: return (a * ((b / c) * 3));
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			varB,
			varC
	));
	ShPtr<MulOpExpr> mulOpExpr1(
		MulOpExpr::create(
			divOpExpr,
			ConstInt::create(3,64)
	));
	ShPtr<MulOpExpr> mulOpExpr2(
		MulOpExpr::create(
			varA,
			mulOpExpr1
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr2));
	testFunc->setBody(returnStmt);
	NoBracketManager noBracketManager(module);

	EXPECT_TRUE(noBracketManager.areBracketsNeeded(divOpExpr)) <<
		"expected brackets around " << divOpExpr;
	EXPECT_TRUE(noBracketManager.areBracketsNeeded(mulOpExpr1)) <<
		"expected brackets around " << mulOpExpr1;
	EXPECT_TRUE(noBracketManager.areBracketsNeeded(mulOpExpr2)) <<
		"expected brackets around " << mulOpExpr2;
}

TEST_F(NoBracketManagerTests,
MulDiv) {
	// return a * (b / c);
	//
	// expected output: return (a * (b / c));
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			varB,
			varC
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			divOpExpr,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	NoBracketManager noBracketManager(module);

	EXPECT_TRUE(noBracketManager.areBracketsNeeded(divOpExpr)) <<
		"expected brackets around " << divOpExpr;
	EXPECT_TRUE(noBracketManager.areBracketsNeeded(mulOpExpr)) <<
		"expected brackets around " << mulOpExpr;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
