/**
* @file tests/llvmir2hll/optimizer/optimizers/dead_local_assign_optimizer_tests.cpp
* @brief Tests for the @c dead_local_assign_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_local_assign_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c dead_local_assign_optimizer module.
*/
class DeadLocalAssignOptimizerTests: public TestsWithModule {};

TEST_F(DeadLocalAssignOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<DeadLocalAssignOptimizer> optimizer(new DeadLocalAssignOptimizer(module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(DeadLocalAssignOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
OptimizeOneUseVarDefStmtNoInitializer) {
	// Set-up the module.
	//
	// def test():
	//     a  (VarDefStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
OptimizeOneUseVarDefStmtWithConstantInitializer) {
	// Set-up the module.
	//
	// def test():
	//     a = 1  (VarDefStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, constInt1));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
OptimizeOneUseAssignStmt) {
	// Set-up the module.
	//
	// def test():
	//     a = 1  (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, constInt1));
	testFunc->setBody(assignA1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
OptimizeTwoUsesConstantOnRhs) {
	// Set-up the module.
	//
	// def test():
	//     a      (VarDefStmt)
	//     a = 1  (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, constInt1));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignA1));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
OptimizeThreeUses) {
	// Set-up the module.
	//
	// g
	//
	// def test():
	//     a      (VarDefStmt)
	//     a = 1  (AssignStmt)
	//     a = g  (AssignStmt)
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(16)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<AssignStmt> assignAG(AssignStmt::create(varA, varG));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, constInt1, assignAG));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignA1));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
OptimizeTwoUsesVariableOnRhs) {
	// Set-up the module.
	//
	// def test():
	//     a      (VarDefStmt)
	//     a = b  (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addParam(varB);
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignAB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
DoNotOptimizeWhenVariablesIsRead) {
	// Set-up the module.
	//
	// def test():
	//     a      (VarDefStmt)
	//     a = 1  (AssignStmt)
	//     return a
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, constInt1, returnA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignA1));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	// a
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, got `" << stmt1 << "`";
	// a = 1
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(assignA1, stmt2) <<
		"expected `" << assignA1 << "`, got `" << stmt2 << "`";
	// return a
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_EQ(returnA, stmt3) <<
		"expected `" << returnA << "`, got `" << stmt3 << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
DoNotOptimizeWhenRhsHasSideEffects) {
	// Set-up the module.
	//
	// def test():
	//     a           (VarDefStmt)
	//     a = rand()  (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varRand(Variable::create("a", IntType::create(16)));
	ShPtr<CallExpr> randCall(CallExpr::create(varRand));
	ShPtr<AssignStmt> assignRand(AssignStmt::create(varA, randCall));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignRand));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	// a
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, got `" << stmt1 << "`";
	// a = rand()
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(assignRand, stmt2) <<
		"expected `" << assignRand << "`, got `" << stmt2 << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
DoNotOptimizeAssignmentOfConstantIntoGlobalVariable) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//     a = 1  (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, constInt1));
	testFunc->setBody(assignA1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt(testFunc->getBody());
	ASSERT_EQ(assignA1, stmt) <<
		"expected `" << assignA1 << "`, got `" << stmt << "`";
}

TEST_F(DeadLocalAssignOptimizerTests,
DoNotOptimizeAssignmentIntoExternalVariable) {
	// Set-up the module.
	//
	// def test():
	//     a = 1  (VarDefStmt, where 'a' is external and comes from a volatile
	//             store)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	varA->markAsExternal();
	testFunc->addLocalVar(varA);
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, constInt1));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<DeadLocalAssignOptimizer>(module, va);

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt) <<
		"expected `" << varDefA << "`, got `" << stmt << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
