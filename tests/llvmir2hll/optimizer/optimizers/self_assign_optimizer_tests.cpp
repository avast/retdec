/**
* @file tests/llvmir2hll/optimizer/optimizers/self_assign_optimizer_tests.cpp
* @brief Tests for the @c self_assign_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/self_assign_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c self_assign_optimizer module.
*/
class SelfAssignOptimizerTests: public TestsWithModule {};

TEST_F(SelfAssignOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<SelfAssignOptimizer> optimizer(new SelfAssignOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(SelfAssignOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<SelfAssignOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

TEST_F(SelfAssignOptimizerTests,
NonAssignStmtsAreNotOptimized) {
	// Add a body to the testing function:
	//
	// return 5 + 10
	//
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstInt::create(llvm::APInt(64, 5)),
			ConstInt::create(llvm::APInt(64, 10))
		));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<SelfAssignOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// return
	ShPtr<ReturnStmt> outFuncBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outFuncBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	// +
	ShPtr<AddOpExpr> outReturnExpr(cast<AddOpExpr>(outFuncBody->getRetVal()));
	ASSERT_TRUE(outReturnExpr) <<
		"expected AddOpExpr, got " << outFuncBody->getRetVal();
	// 5
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outReturnExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outReturnExpr->getFirstOperand();
	EXPECT_EQ(llvm::APInt(64, 5), outOp1->getValue());
	// 10
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outReturnExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outReturnExpr->getSecondOperand();
	EXPECT_EQ(llvm::APInt(64, 10), outOp2->getValue());
}

TEST_F(SelfAssignOptimizerTests,
AssignOfDifferentVariablesIsNotRemoved) {
	// Add a body to the testing function:
	//
	//   a = b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AssignStmt> assignStmt(AssignStmt::create(varA, varB));
	testFunc->setBody(assignStmt);

	// Optimize the module.
	Optimizer::optimize<SelfAssignOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// =
	ShPtr<AssignStmt> outFuncBody(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outFuncBody) <<
		"expected AssignStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!outFuncBody->hasSuccessor()) <<
		"expected no successor, got " << outFuncBody->getSuccessor();
	// a
	ShPtr<Variable> outLhs(cast<Variable>(outFuncBody->getLhs()));
	EXPECT_EQ(varA, outLhs);
	// b
	ShPtr<Variable> outRhs(cast<Variable>(outFuncBody->getRhs()));
	EXPECT_EQ(varB, outRhs);
}

TEST_F(SelfAssignOptimizerTests,
SelfAssignIsRemovedWhenItHasSuccessor) {
	// Add a body to the testing function:
	//
	//   a = a
	//   return
	//
	ShPtr<Variable> var(Variable::create("a", IntType::create(16)));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(var, var,
		ReturnStmt::create())); // successor
	testFunc->setBody(assignStmt);

	// Optimize the module.
	Optimizer::optimize<SelfAssignOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// return
	ShPtr<ReturnStmt> outFuncBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outFuncBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!outFuncBody->getRetVal()) <<
		"expected no return value, got " << outFuncBody->getRetVal();
	EXPECT_TRUE(!outFuncBody->hasSuccessor()) <<
		"expected no successor, got " << outFuncBody->getSuccessor();
}

TEST_F(SelfAssignOptimizerTests,
SelfAssignIsRemovedWhenItHasPredecessor) {
	// Add a body to the testing function:
	//
	//   return
	//   a = a
	//
	ShPtr<Variable> var(Variable::create("a", IntType::create(16)));
	ShPtr<AssignStmt> assignStmt(AssignStmt::create(var, var));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(ShPtr<Expression>(),
		assignStmt));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<SelfAssignOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// return
	ShPtr<ReturnStmt> outFuncBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outFuncBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!outFuncBody->getRetVal()) <<
		"expected no return value, got " << outFuncBody->getRetVal();
	EXPECT_TRUE(!outFuncBody->hasSuccessor()) <<
		"expected no successor, got " << outFuncBody->getSuccessor();
}

TEST_F(SelfAssignOptimizerTests,
FuncWithJustSelfAssignIsOptimizedToEmptyBody) {
	// Add a body to the testing function:
	//
	//   a = a
	//
	ShPtr<Variable> var(Variable::create("a", IntType::create(16)));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(var, var));
	testFunc->setBody(assignStmt);

	// Optimize the module.
	Optimizer::optimize<SelfAssignOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// empty body
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successor, but got " <<
		testFunc->getBody()->getSuccessor();
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
