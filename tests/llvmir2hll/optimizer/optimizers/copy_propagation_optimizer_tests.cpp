/**
* @file tests/llvmir2hll/optimizer/optimizers/copy_propagation_optimizer_tests.cpp
* @brief Tests for the @c copy_propagation_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/copy_propagation_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c copy_propagation_optimizer module.
*/
class CopyPropagationOptimizerTests: public TestsWithModule {};

TEST_F(CopyPropagationOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<CopyPropagationOptimizer> optimizer(new CopyPropagationOptimizer(
		module, va, OptimCallInfoObtainer::create()));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(CopyPropagationOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
LocalVariableInVarDefStmtWithNoUsesGetsRemoved) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
LocalVariableInAssignStmtWithNoUsesGetsRemoved) {
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
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateVarDefStmtWhenVariableHasNameFromDebugInfo) {
	// Set-up the module.
	//
	// void test() {
	//     int d; (the name is assigned from debug information)
	// }
	//
	ShPtr<Variable> varD(Variable::create("d", IntType::create(32)));
	testFunc->addLocalVar(varD);
	module->addDebugNameForVar(varD, varD->getName());
	ShPtr<VarDefStmt> varDefD(VarDefStmt::create(varD));
	testFunc->setBody(varDefD);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(varDefD, testFunc->getBody()) <<
		"expected `" << varDefD << "`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignStmtWhenVariableHasNameFromDebugInfo) {
	// Set-up the module.
	//
	// void test() {
	//     d = 1; (the name is assigned from debug information)
	// }
	//
	ShPtr<Variable> varD(Variable::create("d", IntType::create(32)));
	testFunc->addLocalVar(varD);
	module->addDebugNameForVar(varD, varD->getName());
	ShPtr<AssignStmt> assignD1(AssignStmt::create(varD, ConstInt::create(1, 32)));
	testFunc->setBody(assignD1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignD1, testFunc->getBody()) <<
		"expected `" << assignD1 << "`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignStmtWhenVariableIsExternal) {
	// Set-up the module.
	//
	// void test() {
	//     d = 1; (d is 'external' and comes from a volatile store)
	// }
	//
	ShPtr<Variable> varD(Variable::create("d", IntType::create(32)));
	varD->markAsExternal();
	testFunc->addLocalVar(varD);
	ShPtr<AssignStmt> assignD1(AssignStmt::create(varD, ConstInt::create(1, 32)));
	testFunc->setBody(assignD1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignD1, testFunc->getBody()) <<
		"expected `" << assignD1 << "`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DotNotEliminateAssignIntoGlobalVariableIfThereIsNoSuccessiveAssignIntoIt) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//     g = 1;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32)));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignG1, testFunc->getBody()) <<
		"expected `" << assignG1 << "`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignToGlobalVarIfItIsUsedInTheNextStatement) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//     g = 1;
	//     return g;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<ReturnStmt> returnG(ReturnStmt::create(varG));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), returnG));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignG1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG1, stmt1) <<
		"expected `" << assignG1 << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << returnG << "`, "
		"got the null pointer";
	EXPECT_EQ(returnG, stmt2) <<
		"expected `" << returnG << "`, "
		"got `" << stmt2 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignToGlobalVarIfThereIsFuncCallBeforeTheNextAssign) {
	// Set-up the module.
	//
	// int g;
	// int h;
	//
	// void readG() {
	//     h = g;
	// }
	//
	// void test() {
	//     g = 1;
	//     readG();
	//     g = 2;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varH(Variable::create("h", IntType::create(32)));
	module->addGlobalVar(varH);

	ShPtr<Function> readGFunc = FunctionBuilder("readG")
		.definitionWithBody(AssignStmt::create(varG, varH))
		.build();
	ShPtr<AssignStmt> assignG2(AssignStmt::create(varG, ConstInt::create(2, 32)));
	ShPtr<CallExpr> readGCallExpr(CallExpr::create(readGFunc->getAsVar()));
	ShPtr<CallStmt> readGCall(CallStmt::create(readGCallExpr, assignG2));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), readGCall));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignG1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG1, stmt1) <<
		"expected `" << assignG1 << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << readGCall << "`, "
		"got the null pointer";
	EXPECT_EQ(readGCall, stmt2) <<
		"expected `" << readGCall << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << assignG2 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG2, stmt3) <<
		"expected `" << assignG2 << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignToGlobalVarIfThereMayNotAlwaysBeAnotherAssignToIt) {
	// Set-up the module.
	//
	// int g;
	// int h;
	//
	// void test() {
	//     g = 1;
	//     if (h) {
	//         g = 2;
	//     }
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varH(Variable::create("h", IntType::create(32)));
	module->addGlobalVar(varH);

	ShPtr<AssignStmt> assignG2(AssignStmt::create(varG, ConstInt::create(2, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(varH, assignG2));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), ifStmt));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << assignG1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG1, stmt1) <<
		"expected `" << assignG1 << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << ifStmt << "`, "
		"got the null pointer";
	EXPECT_EQ(ifStmt, stmt2) <<
		"expected `" << ifStmt << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(cast<IfStmt>(stmt2)->getFirstIfBody());
	ASSERT_TRUE(stmt3) <<
		"expected `" << assignG2 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG2, stmt3) <<
		"expected `" << assignG2 << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignToGlobalVarIfItMayBeUsedIndirectly) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//     int *p = &g;
	//     g = 1;
	//     return *p;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varP(Variable::create("p", PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), returnP));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(varP, AddressOpExpr::create(varG), assignG1));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	VarSet refPPointsTo;
	refPPointsTo.insert(varG);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varP))
		.WillByDefault(ReturnRef(refPPointsTo));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varG))
		.WillByDefault(Return(true));

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << varDefP << "`, "
		"got the null pointer";
	EXPECT_EQ(varDefP, stmt1) <<
		"expected `" << varDefP << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignG1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG1, stmt2) <<
		"expected `" << assignG1 << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnP << "`, "
		"got the null pointer";
	EXPECT_EQ(returnP, stmt3) <<
		"expected `" << returnP << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateAssignToGlobalVarIfItMustBeUsedIndirectly) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//     int *p = &g;
	//     g = 1;
	//     return *p;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varP(Variable::create("p", PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), returnP));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(varP, AddressOpExpr::create(varG), assignG1));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varG));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varG))
		.WillByDefault(Return(true));

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << varDefP << "`, "
		"got the null pointer";
	EXPECT_EQ(varDefP, stmt1) <<
		"expected `" << varDefP << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignG1 << "`, "
		"got the null pointer";
	EXPECT_EQ(assignG1, stmt2) <<
		"expected `" << assignG1 << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnP << "`, "
		"got the null pointer";
	EXPECT_EQ(returnP, stmt3) <<
		"expected `" << returnP << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
EliminateConstantInitializerOfVarDefStmtIfNextUseIsWrite) {
	// Set-up the module.
	//
	// void test() {
	//     int a = 0;
	//     a = rand();
	//     return a + a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnAA(ReturnStmt::create(AddOpExpr::create(varA, varA)));
	ShPtr<Variable> varRand(Variable::create("a", IntType::create(16)));
	ShPtr<CallExpr> randCall(CallExpr::create(varRand));
	ShPtr<AssignStmt> assignArand(AssignStmt::create(varA, randCall, returnAA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ConstInt::create(0, 32), assignArand));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output is correct:
	//
	// void test() {
	//     int a;        // no initializer
	//     a = rand();
	//     return a;
	// }
	//
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << varDefA << "`, "
		"got the null pointer";
	ASSERT_TRUE(isa<VarDefStmt>(stmt1)) <<
		"expected a VarDefStmt, got `" << stmt1 << "`";
	EXPECT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, "
		"got `" << stmt1 << "`";
	EXPECT_FALSE(cast<VarDefStmt>(stmt1)->getInitializer()) <<
		"expected varDefA to have no initializer, but got `" <<
		cast<VarDefStmt>(stmt1)->getInitializer() << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignArand << "`, "
		"got the null pointer";
	EXPECT_EQ(assignArand, stmt2) <<
		"expected `" << assignArand << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnAA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnAA, stmt3) <<
		"expected `" << returnAA << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotEliminateInitializerOfVarDefStmtIfItIsNotConstant) {
	// Set-up the module.
	//
	// void test() {
	//     int a = rand();
	//     a = rand();
	//     return a + a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnAA(ReturnStmt::create(AddOpExpr::create(varA, varA)));
	ShPtr<Variable> varRand(Variable::create("a", IntType::create(16)));
	ShPtr<CallExpr> randCall(CallExpr::create(varRand));
	ShPtr<AssignStmt> assignArand(AssignStmt::create(varA, randCall, returnAA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, randCall, assignArand));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << varDefA << "`, "
		"got the null pointer";
	ASSERT_TRUE(isa<VarDefStmt>(stmt1)) <<
		"expected a VarDefStmt, got `" << stmt1 << "`";
	EXPECT_EQ(varDefA, stmt1) <<
		"expected `" << varDefA << "`, "
		"got `" << stmt1 << "`";
	EXPECT_TRUE(cast<VarDefStmt>(stmt1)->getInitializer()) <<
		"expected varDefA to have an initializer";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << assignArand << "`, "
		"got the null pointer";
	EXPECT_EQ(assignArand, stmt2) <<
		"expected `" << assignArand << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `" << returnAA << "`, "
		"got the null pointer";
	EXPECT_EQ(returnAA, stmt3) <<
		"expected `" << returnAA << "`, "
		"got `" << stmt3 << "`";
}

TEST_F(CopyPropagationOptimizerTests,
DoNotPropagateNullPointersToDereferencesOnLeftHandSidesOfAssignStmts) {
	// Set-up the module.
	//
	// void test() {
	//     int *p;
	//     p = NULL;
	//     *p = 1;
	// }
	//
	ShPtr<PointerType> intPtrType(PointerType::create(IntType::create(32)));
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<DerefOpExpr> derefP(DerefOpExpr::create(varP));
	ShPtr<AssignStmt> assignDerefP1(AssignStmt::create(
		derefP, ConstInt::create(1, 32)));
	ShPtr<AssignStmt> assignPNULL(AssignStmt::create(
		varP, ConstNullPointer::create(intPtrType), assignDerefP1));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, ShPtr<Expression>(), assignPNULL));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<CopyPropagationOptimizer>(module, va,
		OptimCallInfoObtainer::create());

	// Check that the output hasn't been changed.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(varP, derefP->getOperand()) <<
		"expected `" << varP << "`, "
		"got `" << derefP->getOperand() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
