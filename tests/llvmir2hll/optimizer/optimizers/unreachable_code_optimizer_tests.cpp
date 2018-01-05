/**
* @file tests/llvmir2hll/optimizer/optimizers/unreachable_code_optimizer_tests.cpp
* @brief Tests for the @c unreachable_code_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/optimizer/optimizers/unreachable_code_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c unreachable_code_optimizer module.
*/
class UnreachableCodeOptimizerTests: public TestsWithModule {};

TEST_F(UnreachableCodeOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<UnreachableCodeOptimizer> optimizer(new UnreachableCodeOptimizer(module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(UnreachableCodeOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Set-up the module.
	//
	// void test() {}

	// Set-up the semantics.
	// -

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<UnreachableCodeOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(UnreachableCodeOptimizerTests,
UnreachableStatementIsAppendedAfterExit) {
	// Set-up the module.
	//
	// void test() {
	//     exit();
	// }
	ShPtr<Function> exitFunc(
		FunctionBuilder("exit")
			.build()
	);
	module->addFunc(exitFunc);
	ShPtr<CallStmt> exitCall(CallStmt::create(CallExpr::create(exitFunc->getAsVar())));
	testFunc->setBody(exitCall);

	// Set-up the semantics.
	ON_CALL(*semanticsMock, funcNeverReturns("exit"))
		.WillByDefault(Return(Just(true)));

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<UnreachableCodeOptimizer>(module, va);

	// Check that the output is correct:
	//
	// void test() {
	//     exit();
	//     // UNREACHABLE
	// }
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << exitCall << "`, "
		"got the null pointer";
	EXPECT_EQ(exitCall, stmt1) <<
		"expected `" << exitCall << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `// UNREACHABLE`, "
		"got the null pointer";
	EXPECT_TRUE(isa<UnreachableStmt>(stmt2)) <<
		"expected `// UNREACHABLE`, "
		"got `" << stmt2 << "`";
}

TEST_F(UnreachableCodeOptimizerTests,
NoStatementIsAppendedAfterReturningFunction) {
	// Set-up the module.
	//
	// void test() {
	//     myexit();
	// }
	ShPtr<Function> exitFunc(
		FunctionBuilder("myexit")
			.build()
	);
	module->addFunc(exitFunc);
	ShPtr<CallStmt> exitCall(CallStmt::create(CallExpr::create(exitFunc->getAsVar())));
	testFunc->setBody(exitCall);

	// Set-up the semantics.
	ON_CALL(*semanticsMock, funcNeverReturns("myexit"))
		.WillByDefault(Return(Nothing<bool>()));

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<UnreachableCodeOptimizer>(module, va);

	// Check that the output is correct:
	//
	// void test() {
	//     myexit();
	// }
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << exitCall << "`, "
		"got the null pointer";
	EXPECT_EQ(exitCall, stmt1) <<
		"expected `" << exitCall << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	EXPECT_FALSE(stmt2) <<
		"expected the null pointer, "
		"got `" << stmt2 << "`";
}

TEST_F(UnreachableCodeOptimizerTests,
CodeAfterExitIsChangedToUnreachable) {
	// Set-up the module.
	//
	// void test() {
	//     exit();
	//     return;
	// }
	ShPtr<Function> exitFunc(
		FunctionBuilder("exit")
			.build()
	);
	module->addFunc(exitFunc);
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<CallStmt> exitCall(CallStmt::create(CallExpr::create(exitFunc->getAsVar(),
		ExprVector()), returnStmt));
	testFunc->setBody(exitCall);

	// Set-up the semantics.
	ON_CALL(*semanticsMock, funcNeverReturns("exit"))
		.WillByDefault(Return(Just(true)));

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<UnreachableCodeOptimizer>(module, va);

	// Check that the output is correct:
	//
	// void test() {
	//     exit();
	//     // UNREACHABLE
	// }
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << exitCall << "`, "
		"got the null pointer";
	EXPECT_EQ(exitCall, stmt1) <<
		"expected `" << exitCall << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `// UNREACHABLE`, "
		"got the null pointer";
	EXPECT_TRUE(isa<UnreachableStmt>(stmt2)) <<
		"expected `// UNREACHABLE`, "
		"got `" << stmt2 << "`";
}

TEST_F(UnreachableCodeOptimizerTests,
CodeBeforeExitIsRemovedUntilAnotherFunctionCallIsEncoutered) {
	// Set-up the module.
	//
	// void test() {
	//     test();
	//     int a = 4;
	//     int b = 5;
	//     exit();
	// }
	ShPtr<Function> exitFunc(
		FunctionBuilder("exit")
			.build()
	);
	module->addFunc(exitFunc);
	ShPtr<CallStmt> exitCall(CallStmt::create(CallExpr::create(exitFunc->getAsVar())));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ConstInt::create(1, 32), exitCall));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ConstInt::create(1, 32), varDefB));
	ShPtr<CallStmt> testCall(CallStmt::create(CallExpr::create(testFunc->getAsVar()), varDefA));
	testFunc->setBody(testCall);

	// Set-up the semantics.
	ON_CALL(*semanticsMock, funcNeverReturns("exit"))
		.WillByDefault(Return(Just(true)));

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<UnreachableCodeOptimizer>(module, va);

	// Check that the output is correct:
	//
	// void test() {
	//     test();
	//     exit();
	//     // UNREACHABLE
	// }
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected `" << testCall << "`, "
		"got the null pointer";
	EXPECT_EQ(testCall, stmt1) <<
		"expected `" << testCall << "`, "
		"got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << exitCall << "`, "
		"got the null pointer";
	EXPECT_EQ(exitCall, stmt2) <<
		"expected `" << exitCall << "`, "
		"got `" << stmt2 << "`";
	ShPtr<Statement> stmt3(stmt2->getSuccessor());
	ASSERT_TRUE(stmt3) <<
		"expected `// UNREACHABLE`, "
		"got the null pointer";
	EXPECT_TRUE(isa<UnreachableStmt>(stmt3)) <<
		"expected `// UNREACHABLE`, "
		"got `" << stmt3 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
