/**
* @file tests/llvmir2hll/optimizer/optimizers/auxiliary_variables_optimizer_tests.cpp
* @brief Tests for the @c auxiliary_variables_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/auxiliary_variables_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c auxiliary_variables_optimizer module.
*/
class AuxiliaryVariablesOptimizerTests: public TestsWithModule {};

TEST_F(AuxiliaryVariablesOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<AuxiliaryVariablesOptimizer> optimizer(new AuxiliaryVariablesOptimizer(
		module, va, OptimCallInfoObtainer::create()));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
OptimizeNoAssignStmtOneUse) {
	// Add a body to the testing function:
	//
	//   a = 1  (VarDefStmt)
	//   b = a  (VarDefStmt)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<VarDefStmt> varDefB(
		VarDefStmt::create(varB, varA, returnB));
	ShPtr<VarDefStmt> varDefA(
		VarDefStmt::create(varA, constInt1, varDefB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// a = 1
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_EQ(varDefA, outVarDefA) <<
		"expected `" << varDefA << "`, got `" << testFunc->getBody() << "`";
	// return a
	ASSERT_TRUE(outVarDefA->hasSuccessor());
	ShPtr<ReturnStmt> outReturnA(cast<ReturnStmt>(outVarDefA->getSuccessor()));
	ASSERT_TRUE(outReturnA) <<
		"expected ReturnStmt, got `" << outVarDefA->getSuccessor() << "`";
	ASSERT_TRUE(outReturnA->getRetVal()) <<
		"expected a return value, got no return value";
	ASSERT_EQ(varA, outReturnA->getRetVal()) <<
		"expected `" << varA->getName() << "`, got `" << outReturnA->getRetVal() << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
OptimizeNoAssignStmtOneUseEvenIfLhsVarIsExternal) {
	// Add a body to the testing function:
	//
	//   a = 1  (VarDefStmt, where 'a' is an 'external' variable comming from a
	//           volatile load/store)
	//   b = a  (VarDefStmt)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	varA->markAsExternal();
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<VarDefStmt> varDefB(
		VarDefStmt::create(varB, varA, returnB));
	ShPtr<VarDefStmt> varDefA(
		VarDefStmt::create(varA, constInt1, varDefB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// a = 1
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_EQ(varDefA, outVarDefA) <<
		"expected `" << varDefA << "`, got `" << testFunc->getBody() << "`";
	// return a
	ASSERT_TRUE(outVarDefA->hasSuccessor());
	ShPtr<ReturnStmt> outReturnA(cast<ReturnStmt>(outVarDefA->getSuccessor()));
	ASSERT_TRUE(outReturnA) <<
		"expected ReturnStmt, got `" << outVarDefA->getSuccessor() << "`";
	ASSERT_TRUE(outReturnA->getRetVal()) <<
		"expected a return value, got no return value";
	ASSERT_EQ(varA, outReturnA->getRetVal()) <<
		"expected `" << varA->getName() << "`, got `" << outReturnA->getRetVal() << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
OptimizeAssignStmtsOneUse) {
	// Add a body to the testing function:
	//
	//   a      (VarDefStmt)
	//   b      (VarDefStmt)
	//   a = 1  (AssignStmt)
	//   b = a  (AssignStmt)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<AssignStmt> assignBA(AssignStmt::create(varB, varA, returnB));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, constInt1, assignBA));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), assignA1));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	// a
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_EQ(varDefA, outVarDefA) <<
		"expected `" << varDefA << "`, got `" << testFunc->getBody() << "`";
	// a = 1
	ASSERT_TRUE(outVarDefA->hasSuccessor());
	ShPtr<AssignStmt> outAssignA1(cast<AssignStmt>(outVarDefA->getSuccessor()));
	ASSERT_EQ(assignA1, outAssignA1) <<
		"expected `" << assignA1 << "`, got `" << outVarDefA->getSuccessor() << "`";
	// return a
	ASSERT_TRUE(outAssignA1->hasSuccessor());
	ShPtr<ReturnStmt> outReturnA(cast<ReturnStmt>(outAssignA1->getSuccessor()));
	ASSERT_TRUE(outReturnA) <<
		"expected ReturnStmt, got `" << outAssignA1->getSuccessor() << "`";
	ASSERT_TRUE(outReturnA->getRetVal()) <<
		"expected a return value, got no return value";
	ASSERT_EQ(varA, outReturnA->getRetVal()) <<
		"expected `" << varA->getName() << "`, got `" << outReturnA->getRetVal() << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
DoNotOptimizeWhenOriginalValueIsUsedAfter) {
	// Add a body to the testing function:
	//
	//   a = 1  (VarDefStmt)
	//   b = a  (VarDefStmt)
	//   return a
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<VarDefStmt> varDefB(
		VarDefStmt::create(varB, varA, returnA));
	ShPtr<VarDefStmt> varDefA(
		VarDefStmt::create(varA, constInt1, varDefB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, got `" << stmt1 << "`";
	// b = a
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(varDefB, stmt2) <<
		"expected `" << varDefB << "`, got `" << stmt2 << "`";
	// return a
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_EQ(returnA, stmt3) <<
		"expected `" << returnA << "`, got `" << stmt3 << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
DoNotOptimizeWhenRhsIsComplexExpression) {
	// Add a body to the testing function:
	//
	//   a = 1      (VarDefStmt)
	//   b = a + 3  (VarDefStmt)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ConstInt> constInt3(ConstInt::create(llvm::APInt(16, 3)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<VarDefStmt> varDefB(
		VarDefStmt::create(varB, AddOpExpr::create(varA, constInt3), returnB));
	ShPtr<VarDefStmt> varDefA(
		VarDefStmt::create(varA, constInt1, varDefB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, got `" << stmt1 << "`";
	// b = a + 3
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(varDefB, stmt2) <<
		"expected `" << varDefB << "`, got `" << stmt2 << "`";
	// return b
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_EQ(returnB, stmt3) <<
		"expected `" << returnB << "`, got `" << stmt3 << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
DoNotOptimizeWhenLhsIsGlobalVariable) {
	// Add a body to the testing function:
	//
	//   global b
	//
	//   a = 1  (VarDefStmt)
	//   b = a  (AssignStmt)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	module->addGlobalVar(varB);
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<AssignStmt> assignBA(
		AssignStmt::create(varB, varA, returnB));
	ShPtr<VarDefStmt> varDefA(
		VarDefStmt::create(varA, constInt1, assignBA));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, got `" << stmt1 << "`";
	// b = a
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(assignBA, stmt2) <<
		"expected `" << assignBA << "`, got `" << stmt2 << "`";
	// return b
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_EQ(returnB, stmt3) <<
		"expected `" << returnB << "`, got `" << stmt3 << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
DoNotOptimizeWhenRhsIsGlobalVariable) {
	// Add a body to the testing function:
	//
	//   global a
	//
	//   a = 1  (AssignStmt)
	//   b = a  (VarDefStmt)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<VarDefStmt> varDefB(
		VarDefStmt::create(varB, varA, returnB));
	ShPtr<AssignStmt> assignA1(
		AssignStmt::create(varA, constInt1, varDefB));
	testFunc->setBody(assignA1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(assignA1, stmt1) <<
		"expected `" << assignA1 << "`, got `" << stmt1 << "`";
	// b = a
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(varDefB, stmt2) <<
		"expected `" << varDefB << "`, got `" << stmt2 << "`";
	// return b
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_EQ(returnB, stmt3) <<
		"expected `" << returnB << "`, got `" << stmt3 << "`";
}

TEST_F(AuxiliaryVariablesOptimizerTests,
DoNotOptimizeWhenAuxiliaryVariableIsExternal) {
	// Add a body to the testing function:
	//
	//   a = 1  (VarDefStmt)
	//   b = a  (VarDefStmt, where 'b' is an 'external' variable comming from a
	//           volatile load/store)
	//   return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	varB->markAsExternal();
	ShPtr<ConstInt> constInt1(ConstInt::create(llvm::APInt(16, 1)));
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<VarDefStmt> varDefB(
		VarDefStmt::create(varB, varA, returnB));
	ShPtr<VarDefStmt> varDefA(
		VarDefStmt::create(varA, constInt1, varDefB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<AuxiliaryVariablesOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	// a = 1
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, got `" << stmt1 << "`";
	// b = a
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_EQ(varDefB, stmt2) <<
		"expected `" << varDefB << "`, got `" << stmt2 << "`";
	// return b
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_EQ(returnB, stmt3) <<
		"expected `" << returnB << "`, got `" << stmt3 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
