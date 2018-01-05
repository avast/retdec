/**
* @file tests/llvmir2hll/optimizer/optimizers/if_structure_optimizer_tests.cpp
* @brief Tests for the @c if_structure_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_structure_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c if_structure_optimizer module.
*/
class IfStructureOptimizerTests: public TestsWithModule {};

TEST_F(IfStructureOptimizerTests,
OptimizerHasNonEmptyID) {
	auto optimizer = std::make_shared<IfStructureOptimizer>(module);

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(IfStructureOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<IfStructureOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

TEST_F(IfStructureOptimizerTests,
Optimization5EmptyElseClauseGetsRemoved) {
	// Set-up the module.
	//
	// int a;
	//
	// void test() {
	//    if (a)
	//        return
	//    else {}
	// }
	//
	auto varA = Variable::create("a", IntType::create(16));
	module->addGlobalVar(varA);
	auto ifStmt = IfStmt::create(varA, ReturnStmt::create());
	ifStmt->setElseClause(EmptyStmt::create());
	testFunc->setBody(ifStmt);

	// Optimize the module.
	Optimizer::optimize<IfStructureOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_TRUE(isa<IfStmt>(testFunc->getBody())) <<
		"expected IfStmt, got " << testFunc->getBody();
	ShPtr<IfStmt> ifStmtOut(cast<IfStmt>(testFunc->getBody()));
	EXPECT_FALSE(ifStmtOut->hasElseClause()) <<
		"the else clause was expected to be removed";
}

TEST_F(IfStructureOptimizerTests,
Optimization5NonemptyElseClauseDoesNotGetRemoved) {
	// Set-up the module.
	//
	// int a;
	//
	// void test() {
	//    if (a)
	//        a = 1
	//    else
	//        a = 2
	// }
	//
	auto varA = Variable::create("a", IntType::create(16));
	module->addGlobalVar(varA);
	auto ifStmt = IfStmt::create(varA,
		AssignStmt::create(varA, ConstInt::create(1, 16)));
	ifStmt->setElseClause(AssignStmt::create(varA, ConstInt::create(2, 16)));
	testFunc->setBody(ifStmt);

	// Optimize the module.
	Optimizer::optimize<IfStructureOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_TRUE(isa<IfStmt>(testFunc->getBody())) <<
		"expected IfStmt, got " << testFunc->getBody();
	ShPtr<IfStmt> ifStmtOut(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(ifStmtOut->hasElseClause()) <<
		"expected the else clause to be there";
	EXPECT_TRUE(isa<AssignStmt>(ifStmtOut->getElseClause())) <<
		"expected the assignment to be there";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
