/**
* @file tests/llvmir2hll/optimizer/optimizers/simple_copy_propagation_optimizer_tests.cpp
* @brief Tests for the @c simple_copy_propagation_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simple_copy_propagation_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c simple_copy_propagation_optimizer module.
*/
class SimpleCopyPropagationOptimizerTests: public TestsWithModule {};

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<SimpleCopyPropagationOptimizer> optimizer(new SimpleCopyPropagationOptimizer(
		module, va, OptimCallInfoObtainer::create()));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
JustAssignStmtDoesNotGetRemoved) {
	// Set-up the module.
	//
	// void test() {
	//     a = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32)));
	testFunc->setBody(assignA1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignA1, testFunc->getBody()) <<
		"expected `" << assignA1 << "`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfLhsMayBeUsedIndirectly) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     ...     // `a` may be used indirectly here
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varB))
		.WillByDefault(Return(false));

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsMayBeUsedIndirectly) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     ...     // `b` may be used indirectly here
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(false));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varB))
		.WillByDefault(Return(true));

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfLhsIsGlobalVariable) {
	// Set-up the module.
	//
	// int a;
	//
	// void test() {
	//     a = b;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsIsModifiedBeforeLhsUse) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     b = 1;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32),
		returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignB1));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignB1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignB1, stmt2) <<
		"expected `" << assignB1 << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt3) <<
		"expected `" << returnA << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfLhsHasAssignedNameFromDebugInformation) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	module->addDebugNameForVar(varA, varA->getName());
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfLhsIsExternalVariable) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;    // a is 'external' and comes from a volatile store
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	varA->markAsExternal();
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsEqualsLhs) {
	// Set-up the module.
	//
	// void test() {
	//     a = a;       // This is optimized in other optimizations.
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAA(AssignStmt::create(varA, varA, returnA));
	testFunc->setBody(assignAA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAA << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAA, stmt1) <<
		"expected `" << assignAA << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsContainsArrayAccess) {
	// Set-up the module.
	//
	// void test() {
	//     a = b[0];
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA,
		ArrayIndexOpExpr::create(varB, ConstInt::create(0, 32)), returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsIsAConstString) {
	// Set-up the module.
	//
	// void test() {
	//     a = "abcd";
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAString(AssignStmt::create(varA,
		ConstString::create("abcd"), returnA));
	testFunc->setBody(assignAString);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAString << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAString, stmt1) <<
		"expected `" << assignAString << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsIsAConstArray) {
	// Set-up the module.
	//
	// void test() {
	//     a = {};
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<ConstArray> constArray(ConstArray::createUninitialized(
		ArrayType::create(IntType::create(32), ArrayType::Dimensions())
	));
	ShPtr<AssignStmt> assignAArray(AssignStmt::create(varA,
		constArray, returnA));
	testFunc->setBody(assignAArray);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAArray << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAArray, stmt1) <<
		"expected `" << assignAArray << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsIsAConstStruct) {
	// Set-up the module.
	//
	// void test() {
	//     a = {};
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAStruct(AssignStmt::create(varA,
		ConstStruct::create(ConstStruct::Type(),
			StructType::create(StructType::ElementTypes())), returnA));
	testFunc->setBody(assignAStruct);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAStruct << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAStruct, stmt1) <<
		"expected `" << assignAStruct << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfRhsContainsStructAccess) {
	// Set-up the module.
	//
	// void test() {
	//     a = b['0'];
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA,
		StructIndexOpExpr::create(varB, ConstInt::create(0, 32)), returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt2) <<
		"expected `" << returnA << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfLhsIsModifiedBeforeItIsUsed) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     a = 1;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32),
		returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignA1));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignA1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignA1, stmt2) <<
		"expected `" << assignA1 << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt3) <<
		"expected `" << returnA << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfLhsIsAssignedValueInIf) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     if (1) {
	//         a = c;
	//     }
	//     c = a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignAC,
		assignCA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, ifStmt));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << ifStmt << "`, "
		"got the null pointer";
	EXPECT_EQ(ifStmt, stmt2) <<
		"expected `" << ifStmt << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(ifStmt->getFirstIfBody());
	ASSERT_TRUE(stmt3) <<
		"expected `" << assignAC << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAC, stmt3) <<
		"expected `" << assignAC << "`, "
		"got `" << stmt3 << "`";
	ShPtr<Statement> stmt4(ifStmt->getSuccessor());
	ASSERT_TRUE(stmt4) <<
		"expected `" << assignCA << "`, "
		"got the null pointer";
	EXPECT_EQ(assignCA, stmt4) <<
		"expected `" << assignCA << "`, "
		"got `" << stmt4 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfThereIsFunctionCallAfterOrigStmtThatModifiesRhs) {
	// Set-up the module.
	//
	// int b;
	//
	// void setB() {
	//     b = 1;
	// }
	//
	// void test() {
	//     a = b;
	//     setB();
	//     return a;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	module->addGlobalVar(varB);
	// setB:
	ShPtr<Function> setB(
		FunctionBuilder("setB")
			.definitionWithBody(AssignStmt::create(varB, ConstInt::create(1, 32)))
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(setB);
	// test:
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<CallStmt> setBCall(CallStmt::create(CallExpr::create(setB->getAsVar()),
		returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, setBCall));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignAB << "`, "
		"got the null pointer";
	EXPECT_EQ(assignAB, stmt1) <<
		"expected `" << assignAB << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << setBCall << "`, "
		"got the null pointer";
	EXPECT_EQ(setBCall, stmt2) <<
		"expected `" << setBCall << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(setBCall->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnA, stmt3) <<
		"expected `" << returnA << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfSingleUseAfterOriginalStatementWithVarDef) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	//     a = b;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(),
		assignAB));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<ReturnStmt> returnB(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(returnB) <<
		"expected a return statement, got `" << testFunc << "`";
	EXPECT_EQ(varB, returnB->getRetVal()) <<
		"expected `" << varB << "` as the return value, "
		"got `" << returnB->getRetVal() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfSingleUseAfterOriginalStatementNoVarDef) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, returnA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<ReturnStmt> returnB(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(returnB) <<
		"expected a return statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(varB, returnB->getRetVal()) <<
		"expected `" << varB << "` as the return value, "
		"got `" << returnB->getRetVal() << "`";
}

// TODO Currently, this type of optimization is disabled.
#if 0
TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfSingleUseAfterOriginalStatementRhsIsExpressionNoVarDef) {
	// Set-up the module.
	//
	// void test() {
	//     a = b + 1;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AddOpExpr> addB1(AddOpExpr::create(varB, ConstInt::create(1, 32)));
	ShPtr<AssignStmt> assignAB1(AssignStmt::create(varA, addB1, returnA));
	testFunc->setBody(assignAB1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<ReturnStmt> returnB(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(returnB) <<
		"expected a return statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(addB1, returnB->getRetVal()) <<
		"expected `" << addB1 << "` as the return value, "
		"got `" << returnB->getRetVal() << "`";
}
#endif

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfTwoUsesAfterOriginalStatementNoVarDef) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     c = a;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA, returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignCA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<AssignStmt> assignCB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(assignCB) <<
		"expected an assign statement, got " << testFunc->getBody() << "`";
	EXPECT_EQ(varB, assignCB->getRhs()) <<
		"expected `" << varB << "` as the right-hand side, "
		"got `" << assignCB->getRhs() << "`";
	ShPtr<ReturnStmt> returnB(cast<ReturnStmt>(assignCB->getSuccessor()));
	ASSERT_TRUE(returnB) <<
		"expected a return statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(varB, returnB->getRetVal()) <<
		"expected `" << varB << "` as the return value, "
		"got `" << returnB->getRetVal() << "`";
}

// TODO Currently, this type of optimization is disabled.
#if 0
TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfTwoUsesAfterOriginalStatementRhsIsExpressionNoVarDef) {
	// Set-up the module.
	//
	// void test() {
	//     a = b + d;
	//     c = a;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<Variable> varD(Variable::create("d", IntType::create(32)));
	testFunc->addLocalVar(varD);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA, returnA));
	ShPtr<AddOpExpr> addBD(AddOpExpr::create(varB, varD));
	ShPtr<AssignStmt> assignABD(AssignStmt::create(varA, addBD, assignCA));
	testFunc->setBody(assignABD);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<AssignStmt> assignCAddBD(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(assignCAddBD) <<
		"expected an assign statement statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(addBD, assignCAddBD->getRhs()) <<
		"expected `" << addBD << "` as the right-hand side, "
		"got `" << assignCAddBD->getRhs() << "`";
	ShPtr<ReturnStmt> returnB(cast<ReturnStmt>(assignCAddBD->getSuccessor()));
	ASSERT_TRUE(returnB) <<
		"expected a return statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(addBD, returnB->getRetVal()) <<
		"expected `" << addBD << "` as the return value, "
		"got `" << returnB->getRetVal() << "`";
}
#endif

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfRhsModifiedAfterTheOnlyUseOfLhsAndFuncReturnsRightAfterThat) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     c = a;
	//     b = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32)));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA, assignB1));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignCA));
	testFunc->setBody(assignAB);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<AssignStmt> assignCB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(assignCB) <<
		"expected a return statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(varB, assignCB->getRhs()) <<
		"expected `" << varB << "` as the right-hand side, "
		"got `" << assignCB->getRhs() << "`";
	EXPECT_EQ(assignB1, assignCB->getSuccessor()) <<
		"expected `" << assignB1 << "`, got `" << assignCB->getSuccessor() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfOrigStatementHasFunctionCallOnItsRightHandSide) {
	// Set-up the module.
	//
	// void test() {
	//     a = test();
	//     b = a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<AssignStmt> assignBA(AssignStmt::create(varB, varA));
	ShPtr<CallExpr> testCall(CallExpr::create(testFunc->getAsVar()));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCall, assignBA));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<AssignStmt> assignBTest(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(assignBTest) <<
		"expected an assign statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(testCall, assignBTest->getRhs()) <<
		"expected `" << testCall << "` as the right-hand side, "
		"got `" << assignBTest->getRhs() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfOrigStatementHasFunctionCallOnItsRightHandSideAndNextIsCallStatement) {
	// Set-up the module.
	//
	// void foo(int a);
	//
	// void test() {
	//     a = test();
	//     foo(a);
	// }
	//
	addFuncDecl("foo");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<CallExpr> testCallExpr(CallExpr::create(testFunc->getAsVar()));
	ExprVector fooCallArgs;
	fooCallArgs.push_back(varA);
	ShPtr<CallExpr> fooCallExpr(CallExpr::create(
		module->getFuncByName("foo")->getAsVar(), fooCallArgs));
	ShPtr<CallStmt> fooCallStmt(CallStmt::create(fooCallExpr));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCallExpr, fooCallStmt));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<CallStmt> fooCallStmtNew(cast<CallStmt>(testFunc->getBody()));
	ASSERT_TRUE(fooCallStmtNew) <<
		"expected a call statement, got `" << testFunc->getBody() << "`";
	ShPtr<CallExpr> fooCallArgNew(cast<CallExpr>(fooCallStmtNew->getCall()));
	ASSERT_TRUE(fooCallArgNew) <<
		"expected a call expression, got `" << fooCallArgNew << "`";
	EXPECT_EQ(testCallExpr, fooCallArgNew->getArgs().front()) <<
		"expected `" << testCallExpr << "`, "
		"got `" << fooCallArgNew->getArgs().front() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfOrigStatementHasFunctionCallOnItsRightHandSideAndNextIsReturnStatementWithCall) {
	// Set-up the module.
	//
	// void foo(int a);
	//
	// void test() {
	//     a = test();
	//     return foo(a);
	// }
	//
	addFuncDecl("foo");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<CallExpr> testCallExpr(CallExpr::create(testFunc->getAsVar()));
	ExprVector fooCallArgs;
	fooCallArgs.push_back(varA);
	ShPtr<CallExpr> fooCallExpr(CallExpr::create(
		module->getFuncByName("foo")->getAsVar(), fooCallArgs));
	ShPtr<ReturnStmt> returnFoo(ReturnStmt::create(fooCallExpr));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCallExpr, returnFoo));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<ReturnStmt> returnFooNew(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(returnFooNew) <<
		"expected a return statement, got `" << testFunc->getBody() << "`";
	ShPtr<CallExpr> fooCallArgNew(cast<CallExpr>(returnFooNew->getRetVal()));
	ASSERT_TRUE(fooCallArgNew) <<
		"expected a call expression, got `" << fooCallArgNew << "`";
	EXPECT_EQ(testCallExpr, fooCallArgNew->getArgs().front()) <<
		"expected `" << testCallExpr << "`, "
		"got `" << fooCallArgNew->getArgs().front() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfOrigStatementHasFunctionCallOnItsRightHandSideAndNextIsAssignStatementWithCall) {
	// Set-up the module.
	//
	// void foo(int a);
	//
	// void test() {
	//     a = test();
	//     b = foo(a);
	// }
	//
	addFuncDecl("foo");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<CallExpr> testCallExpr(CallExpr::create(testFunc->getAsVar()));
	ExprVector fooCallArgs;
	fooCallArgs.push_back(varA);
	ShPtr<CallExpr> fooCallExpr(CallExpr::create(
		module->getFuncByName("foo")->getAsVar(), fooCallArgs));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<AssignStmt> assignBFoo(AssignStmt::create(varB, fooCallExpr));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCallExpr, assignBFoo));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<AssignStmt> assignBFooNew(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(assignBFooNew) <<
		"expected an assign statement, got `" << testFunc->getBody() << "`";
	ShPtr<CallExpr> fooCallArgNew(cast<CallExpr>(assignBFoo->getRhs()));
	ASSERT_TRUE(fooCallArgNew) <<
		"expected a call expression, got `" << fooCallArgNew << "`";
	EXPECT_EQ(testCallExpr, fooCallArgNew->getArgs().front()) <<
		"expected `" << testCallExpr << "`, "
		"got `" << fooCallArgNew->getArgs().front() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfOrigStatementHasFunctionCallOnItsRightHandSideAndTheUseIsNotNextStatementButCanBeOptimized) {
	// Set-up the module.
	//
	// void test() {
	//     a = test();
	//     b = 1;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32),
		returnA));
	ShPtr<CallExpr> testCall(CallExpr::create(testFunc->getAsVar()));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCall, assignB1));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<AssignStmt> assignBTest(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(assignBTest) <<
		"expected an assign statement, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(varB, assignBTest->getLhs()) <<
		"expected `" << varB << "` as the left-hand side, "
		"got `" << assignBTest->getLhs() << "`";
	EXPECT_EQ(testCall, returnA->getRetVal()) <<
		"expected `" << testCall << "` as the right-hand side, "
		"got `" << returnA->getRetVal() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
OptimizeIfOrigStatementHasFunctionCallOnItsRightHandSideAndUseIsIfStmt) {
	// Set-up the module.
	//
	// void test() {
	//     a = test();
	//     if (a == 1) {
	//         return;
	//     }
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<EqOpExpr> ifCond(EqOpExpr::create(varA, ConstInt::create(1, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ifCond, returnStmt));
	ShPtr<CallExpr> testCall(CallExpr::create(testFunc->getAsVar()));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCall, ifStmt));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_EQ(ifStmt, testFunc->getBody()) <<
		"expected `" << ifStmt << "`, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(testCall, ifCond->getFirstOperand()) <<
		"expected `" << testCall << "` as the right-hand side, "
		"got `" << ifCond->getFirstOperand() << "`";
}

TEST_F(SimpleCopyPropagationOptimizerTests,
DoNotOptimizeIfThereIsAStatementBetweenCallAndUseThatUsesAVariableFromTheCall) {
	// Set-up the module.
	//
	// void test() {
	//     a = test(c);
	//     c = 1;
	//     b = a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignBA(AssignStmt::create(varB, varA));
	ShPtr<AssignStmt> assignC1(AssignStmt::create(varC, ConstInt::create(1, 32),
		assignBA));
	ExprVector testCallArgs;
	testCallArgs.push_back(varC);
	ShPtr<CallExpr> testCall(CallExpr::create(testFunc->getAsVar(), testCallArgs));
	ShPtr<AssignStmt> assignATest(AssignStmt::create(varA, testCall, assignC1));
	testFunc->setBody(assignATest);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<SimpleCopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignATest << "`, "
		"got the null pointer";
	EXPECT_EQ(assignATest, stmt1) <<
		"expected `" << assignATest << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignC1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignC1, stmt2) <<
		"expected `" << assignC1 << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << assignBA << "`, "
		"got the null pointer";
	EXPECT_EQ(assignBA, stmt3) <<
		"expected `" << assignBA << "`, "
		"got `" << stmt3 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
