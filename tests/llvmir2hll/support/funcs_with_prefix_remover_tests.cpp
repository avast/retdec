/**
* @file tests/llvmir2hll/support/funcs_with_prefix_remover_tests.cpp
* @brief Tests for the @c funcs_with_prefix_remover module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/funcs_with_prefix_remover.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c funcs_with_prefix_remover module.
*/
class FuncsWithPrefixRemoverTests: public TestsWithModule {};

TEST_F(FuncsWithPrefixRemoverTests,
DoNotRemoveAnythingIfThereIsNothingToRemove) {
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

	// Perform the removal.
	FuncsWithPrefixRemover::removeFuncs(module, "to_remove_");

	// Check that the output is correct.
	EXPECT_TRUE(module->getFuncByName("test"));
	EXPECT_EQ(ShPtr<Expression>(), varDefA->getInitializer());
}

TEST_F(FuncsWithPrefixRemoverTests,
RemoveCallToFuncInAssignStmtAndItsDeclaration) {
	// Set-up the module.
	//
	// int to_remove_i();
	//
	// void test() {
	//     int a;
	//     a = to_remove_i();
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Function> toRemoveFunc(
		FunctionBuilder("to_remove_i")
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(toRemoveFunc);
	ShPtr<CallExpr> toRemoveCallExpr(CallExpr::create(toRemoveFunc->getAsVar()));
	ShPtr<AssignStmt> assignAToRemoveCallExpr(AssignStmt::create(varA, toRemoveCallExpr));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignAToRemoveCallExpr));
	testFunc->setBody(varDefA);

	// Perform the removal.
	FuncsWithPrefixRemover::removeFuncs(module, "to_remove_");

	// Check that the output is correct.
	EXPECT_FALSE(module->getFuncByName("to_remove_i"));
	EXPECT_FALSE(varDefA->hasSuccessor());
}

TEST_F(FuncsWithPrefixRemoverTests,
RemoveCallToFuncInVarDefStmtAndItsDeclaration) {
	// Set-up the module.
	//
	// int to_remove_i();
	//
	// void test() {
	//     int a = to_remove_i();
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Function> toRemoveFunc(
		FunctionBuilder("to_remove_i")
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(toRemoveFunc);
	ShPtr<CallExpr> toRemoveCallExpr(CallExpr::create(toRemoveFunc->getAsVar()));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, toRemoveCallExpr));
	testFunc->setBody(varDefA);

	// Perform the removal.
	FuncsWithPrefixRemover::removeFuncs(module, "to_remove_");

	// Check that the output is correct.
	EXPECT_FALSE(module->getFuncByName("to_remove_i"));
	EXPECT_FALSE(varDefA->hasInitializer());
}

TEST_F(FuncsWithPrefixRemoverTests,
RemoveCallToFuncAsSingleCallStatement) {
	// Set-up the module.
	//
	// void to_remove_i();
	//
	// void test() {
	//     to_remove_i();
	// }
	//
	ShPtr<Function> toRemoveFunc(
		FunctionBuilder("to_remove_i")
			.build()
	);
	module->addFunc(toRemoveFunc);
	ShPtr<CallExpr> toRemoveCallExpr(CallExpr::create(toRemoveFunc->getAsVar()));
	ShPtr<CallStmt> toRemoveCallStmt(CallStmt::create(toRemoveCallExpr));
	testFunc->setBody(toRemoveCallStmt);

	// Perform the removal.
	FuncsWithPrefixRemover::removeFuncs(module, "to_remove_");

	// Check that the output is correct.
	EXPECT_FALSE(module->getFuncByName("to_remove_i"));
	EXPECT_TRUE(isa<EmptyStmt>(testFunc->getBody()));
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor());
}

TEST_F(FuncsWithPrefixRemoverTests,
DoNotRemoveFuncIfItsNameDoesNotContainPrefix) {
	// Set-up the module.
	//
	// int not_to_remove();
	//
	// void test() {
	//     int a = not_to_remove();
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Function> notToRemoveFunc(
		FunctionBuilder("not_to_remove")
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(notToRemoveFunc);
	ShPtr<CallExpr> notToRemoveCallExpr(CallExpr::create(notToRemoveFunc->getAsVar()));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, notToRemoveCallExpr));
	testFunc->setBody(varDefA);

	// Perform the removal.
	FuncsWithPrefixRemover::removeFuncs(module, "to_remove_");

	// Check that the output is correct.
	EXPECT_TRUE(module->getFuncByName("not_to_remove"));
	EXPECT_TRUE(varDefA->hasInitializer());
}

TEST_F(FuncsWithPrefixRemoverTests,
WhenMultiplePrefixesAreGivenFuncsWithNamesStartingWithSuchPrefixesAreRemoved) {
	// Set-up the module.
	//
	// void to_remove_i();
	// void another_to_remove_j();
	// void do_not_remove();
	//
	// void test() {
	//     to_remove_i();
	//     another_to_remove_j();
	//     do_not_remove();
	// }
	//
	ShPtr<Function> toRemoveFunc(
		FunctionBuilder("to_remove_i")
			.build()
	);
	module->addFunc(toRemoveFunc);
	ShPtr<CallExpr> toRemoveCallExpr(CallExpr::create(toRemoveFunc->getAsVar()));
	ShPtr<CallStmt> toRemoveCallStmt(CallStmt::create(toRemoveCallExpr));
	testFunc->setBody(toRemoveCallStmt);

	ShPtr<Function> anotherToRemoveFunc(
		FunctionBuilder("another_to_remove_j")
			.build()
	);
	module->addFunc(anotherToRemoveFunc);
	ShPtr<CallExpr> anotherToRemoveCallExpr(CallExpr::create(anotherToRemoveFunc->getAsVar()));
	ShPtr<CallStmt> anotherToRemoveCallStmt(CallStmt::create(anotherToRemoveCallExpr));
	Statement::mergeStatements(testFunc->getBody(), anotherToRemoveCallStmt);

	ShPtr<Function> doNotRemoveFunc(
		FunctionBuilder("do_not_remove")
			.build()
	);
	module->addFunc(doNotRemoveFunc);
	ShPtr<CallExpr> doNotRemoveCallExpr(CallExpr::create(doNotRemoveFunc->getAsVar()));
	ShPtr<CallStmt> doNotRemoveCallStmt(CallStmt::create(doNotRemoveCallExpr));
	Statement::mergeStatements(testFunc->getBody(), doNotRemoveCallStmt);

	// Perform the removal.
	StringSet prefixes;
	prefixes.insert("to_remove_");
	prefixes.insert("another_to_remove_");
	FuncsWithPrefixRemover::removeFuncs(module, prefixes);

	// Check that the output is correct.
	EXPECT_FALSE(module->getFuncByName("to_remove_i"));
	EXPECT_FALSE(module->getFuncByName("another_to_remove_j"));
	EXPECT_TRUE(module->getFuncByName("do_not_remove"));
	EXPECT_EQ(doNotRemoveCallStmt, testFunc->getBody()) <<
		"expected `" << doNotRemoveCallStmt <<
		"` got " << testFunc->getBody();
}

#if DEATH_TESTS_ENABLED
TEST_F(FuncsWithPrefixRemoverTests,
ViolatedPreconditionNullModule) {
	EXPECT_DEATH(FuncsWithPrefixRemover::removeFuncs(ShPtr<Module>(), "to_remove_"),
		".*removeFuncs.*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
