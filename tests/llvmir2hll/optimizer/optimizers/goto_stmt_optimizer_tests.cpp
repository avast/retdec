/**
* @file tests/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer_tests.cpp
* @brief Tests for the @c goto_stmt_optimizer module.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/goto_stmt_optimizer.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c empty_stmt_optimizer module.
*/
class GotoStmtOptimizerTests: public TestsWithModule {};

TEST_F(GotoStmtOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<GotoStmtOptimizer> optimizer(
		new GotoStmtOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

// goto label
// ...
// label:
//   goto/return/break/continue

TEST_F(GotoStmtOptimizerTests,
Goto2Return) {
	// int a
	// goto label
	// a = 1 (...)
	// label:
	//   return 2
	//
	// Can be optimized to:
	// int a
	// return 2
	// a = 1 (...)
	// return 2
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	auto retStmt = ReturnStmt::create(ConstInt::create(1, 64));
	auto assignA = AssignStmt::create(varA, ConstInt::create(1, 32), retStmt);
	auto gotoStmt = GotoStmt::create(retStmt);
	gotoStmt->setSuccessor(assignA);
	testFunc->setBody(gotoStmt);

	Optimizer::optimize<GotoStmtOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ReturnStmt> outRetStmt1(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outRetStmt1) << "expected ReturnStmt, got" << testFunc->getBody();
	ShPtr<AssignStmt> outAssignA(cast<AssignStmt>(outRetStmt1->getSuccessor()));
	ASSERT_TRUE(outAssignA) << "expected AssignStmt, got " << outRetStmt1->getSuccessor();
	ShPtr<ReturnStmt> outRetStmt2(cast<ReturnStmt>(outAssignA->getSuccessor()));
	ASSERT_TRUE(outRetStmt2) << "expected ReturnStmt, got" << outAssignA->getSuccessor();
}

TEST_F(GotoStmtOptimizerTests,
Goto2Break) {
	// int a
	// goto label
	// a = 1 (...)
	// label:
	//   break
	//
	// Can be optimized to:
	// int a
	// break
	// a = 1 (...)
	// break
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	auto breakStmt = BreakStmt::create();
	auto assignA = AssignStmt::create(varA, ConstInt::create(1, 32), breakStmt);
	auto gotoStmt = GotoStmt::create(breakStmt); //, assignA);
	gotoStmt->setSuccessor(assignA);
	testFunc->setBody(gotoStmt);

	Optimizer::optimize<GotoStmtOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<BreakStmt> outBreakStmt1(cast<BreakStmt>(testFunc->getBody()));
	ASSERT_TRUE(outBreakStmt1) << "expected BreakStmt, got" << testFunc->getBody();
	ShPtr<AssignStmt> outAssignA(cast<AssignStmt>(outBreakStmt1->getSuccessor()));
	ASSERT_TRUE(outAssignA) << "expected AssignStmt, got " << outBreakStmt1->getSuccessor();
	ShPtr<BreakStmt> outBreakStmt2(cast<BreakStmt>(outAssignA->getSuccessor()));
	ASSERT_TRUE(outBreakStmt2) << "expected BreakStmt, got" << outAssignA->getSuccessor();
}

TEST_F(GotoStmtOptimizerTests,
Goto2Continue) {
	// int a
	// goto label
	// a = 1 (...)
	// label:
	//   continue
	//
	// Can be optimized to:
	// int a
	// continue
	// a = 1 (...)
	// continue
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	auto continueStmt = ContinueStmt::create();
	auto assignA = AssignStmt::create(varA, ConstInt::create(1, 32), continueStmt);
	auto gotoStmt = GotoStmt::create(continueStmt); //, assignA);
	gotoStmt->setSuccessor(assignA);
	testFunc->setBody(gotoStmt);

	Optimizer::optimize<GotoStmtOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ContinueStmt> outContinueStmt1(cast<ContinueStmt>(testFunc->getBody()));
	ASSERT_TRUE(outContinueStmt1) << "expected ContinueStmt, got" << testFunc->getBody();
	ShPtr<AssignStmt> outAssignA(cast<AssignStmt>(outContinueStmt1->getSuccessor()));
	ASSERT_TRUE(outAssignA) << "expected AssignStmt, got " << outContinueStmt1->getSuccessor();
	ShPtr<ContinueStmt> outContinueStmt2(cast<ContinueStmt>(outAssignA->getSuccessor()));
	ASSERT_TRUE(outContinueStmt2) << "expected ContinueStmt, got" << outAssignA->getSuccessor();
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
