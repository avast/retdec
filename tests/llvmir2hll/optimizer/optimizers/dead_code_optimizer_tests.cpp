/**
* @file tests/llvmir2hll/optimizer/optimizers/dead_code_optimizer_tests.cpp
* @brief Tests for the @c dead_code_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_code_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c dead_code_optimizer module.
*/
class DeadCodeOptimizerTests: public TestsWithModule {
protected:
	void optimize(Module* module);
};

void DeadCodeOptimizerTests::optimize(Module* module) {
	ArithmExprEvaluator* evaluator(StrictArithmExprEvaluator::
		create());
	Optimizer::optimize<DeadCodeOptimizer>(module, evaluator);
}

TEST_F(DeadCodeOptimizerTests,
OptimizerHasNonEmptyID) {
	ArithmExprEvaluator* evaluator(StrictArithmExprEvaluator::
		create());
	DeadCodeOptimizer* optimizer(
		new DeadCodeOptimizer(module, evaluator));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for ForLoopStmt
//

TEST_F(DeadCodeOptimizerTests,
ForLoopStmtEndCondWithIndVarEvaluatedToFalseIsOptimized) {
	// for (i = 5; i < 4; i++) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3
	//
	// Can be optimized to
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	ForLoopStmt* forLoopStmt(
		ForLoopStmt::create(
			varI,
			ConstInt::create(5, 64),
			ltOpExpr,
			ConstInt::create(1, 64),
			assignStmtB,
			assignStmtA
	));
	testFunc->setBody(forLoopStmt);

	optimize(module);

	AssignStmt* outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmt) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmt, assignStmtA) <<
		"expected `" << assignStmtA << "`, "
		"got `" << outAssignStmt << "`";
}

TEST_F(DeadCodeOptimizerTests,
ForLoopStmtEndCondEvaluatedToFalseIsOptimized) {
	// for (i = 5; false; i++) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3
	//
	// Can be optimized to
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	ForLoopStmt* forLoopStmt(
		ForLoopStmt::create(
			varI,
			ConstInt::create(5, 64),
			ConstBool::create(false),
			ConstInt::create(1, 64),
			assignStmtB,
			assignStmtA
	));
	testFunc->setBody(forLoopStmt);

	optimize(module);

	AssignStmt* outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmt) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmt, assignStmtA) <<
		"expected `" << assignStmtA << "`, "
		"got `" << outAssignStmt << "`";
}

TEST_F(DeadCodeOptimizerTests,
ForLoopStmtEndCondWithIndVarEvaluatedToFalseWithGotoLabelNotOptimized) {
	// for (i = 5; i < 4; i++) {
	//     label: b = 2 + 4;
	// }
	// a = 1 + 3
	//
	// Can't be optimized because body of for loop has goto label.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	GotoStmt::create(assignStmtB);
	ForLoopStmt* forLoopStmt(
		ForLoopStmt::create(
			varI,
			ConstInt::create(5, 64),
			ltOpExpr,
			ConstInt::create(1, 64),
			assignStmtB,
			assignStmtA
	));
	testFunc->setBody(forLoopStmt);

	optimize(module);

	ForLoopStmt* outForLoopStmt(cast<ForLoopStmt>(testFunc->getBody()));
	ASSERT_TRUE(outForLoopStmt) <<
		"expected `ForLoopStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(DeadCodeOptimizerTests,
ForLoopStmtEndCondWithIndVarCantBeEvaluatedNotOptimized) {
	// for (i = 5; a + i < 4; i++) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3
	//
	// Can't be optimized because end condition can't be evaluated. We don't
	// know value of variable A
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	AddOpExpr* addOpExprEndCond(
		AddOpExpr::create(
			varA,
			varI
	));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			addOpExprEndCond,
			ConstInt::create(4, 64)
	));
	ForLoopStmt* forLoopStmt(
		ForLoopStmt::create(
			varI,
			ConstInt::create(5, 64),
			ltOpExpr,
			ConstInt::create(1, 64),
			assignStmtB,
			assignStmtA
	));
	testFunc->setBody(forLoopStmt);

	optimize(module);

	ForLoopStmt* outForLoopStmt(cast<ForLoopStmt>(testFunc->getBody()));
	ASSERT_TRUE(outForLoopStmt) <<
		"expected `ForLoopStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(DeadCodeOptimizerTests,
ForLoopStmtEndCondWithIndVarEvaluatedToTrueNotOptimized) {
	// for (i = 5; i > 4; i++) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3
	//
	// Can't be optimized because end condition is evaluated as true.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	GtOpExpr* ltOpExpr(
		GtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	ForLoopStmt* forLoopStmt(
		ForLoopStmt::create(
			varI,
			ConstInt::create(5, 64),
			ltOpExpr,
			ConstInt::create(1, 64),
			assignStmtB,
			assignStmtA
	));
	testFunc->setBody(forLoopStmt);

	optimize(module);

	ForLoopStmt* outForLoopStmt(cast<ForLoopStmt>(testFunc->getBody()));
	ASSERT_TRUE(outForLoopStmt) <<
		"expected `ForLoopStmt`, "
		"got `" << testFunc->getBody() << "`";
}

//
// Tests for WhileLoopStmt
//

TEST_F(DeadCodeOptimizerTests,
WhileLoopStmtWithBoolCondEvaluatedToFalseIsOptimized) {
	// while (false) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3
	//
	// Can be optimized to
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExprInWhile(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtInWhile(
		AssignStmt::create(
			varB,
			addOpExprInWhile
	));
	AddOpExpr* addOpExprOutWhile(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtOutWhile(
		AssignStmt::create(
			varA,
			addOpExprOutWhile
	));
	WhileLoopStmt* whileLoopStmt(
		WhileLoopStmt::create(
			ConstBool::create(false),
			assignStmtInWhile,
			assignStmtOutWhile
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	AssignStmt* outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmt) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmt, assignStmtOutWhile) <<
		"expected `" << assignStmtOutWhile << "`, "
		"got `" << outAssignStmt << "`";
}

TEST_F(DeadCodeOptimizerTests,
WhileLoopStmtWithFloatCondEvaluatedToFalseIsOptimized) {
	// while (2.0 - 2.0) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	AddOpExpr* addOpExprInWhile(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtInWhile(
		AssignStmt::create(
			varB,
			addOpExprInWhile
	));
	AddOpExpr* addOpExprOutWhile(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtOutWhile(
		AssignStmt::create(
			varA,
			addOpExprOutWhile
	));
	WhileLoopStmt* whileLoopStmt(
		WhileLoopStmt::create(
			subOpExpr,
			assignStmtInWhile,
			assignStmtOutWhile
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	AssignStmt* outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmt) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmt, assignStmtOutWhile) <<
		"expected `" << assignStmtOutWhile << "`, "
		"got `" << outAssignStmt << "`";
}

TEST_F(DeadCodeOptimizerTests,
WhileLoopStmtWithBoolCondEvaluatedToTrueNotOptimized) {
	// while (true) {
	//     b = 2 + 4;
	// }
	//
	// Not optimized because we don't want optimize infinite while loop.
	//
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	WhileLoopStmt* whileLoopStmt(
		WhileLoopStmt::create(
			ConstBool::create(true),
			assignStmt
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	WhileLoopStmt* outWhileLoopStmt(cast<WhileLoopStmt>(testFunc->getBody()));
	ASSERT_TRUE(outWhileLoopStmt) <<
		"expected `WhileLoopStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(DeadCodeOptimizerTests,
WhileLoopStmtWithBoolCondEvaluatedToFalseWithGotoLabelNotOptimized) {
	// while (false) {
	//     label: b = 2 + 4;
	// }
	//
	// Not optimized because body of while loop contains goto label.
	//
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	GotoStmt::create(assignStmt);
	WhileLoopStmt* whileLoopStmt(
		WhileLoopStmt::create(
			ConstBool::create(true),
			assignStmt
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	WhileLoopStmt* outWhileLoopStmt(cast<WhileLoopStmt>(testFunc->getBody()));
	ASSERT_TRUE(outWhileLoopStmt) <<
		"expected `WhileLoopStmt`, "
		"got `" << testFunc->getBody() << "`";
}

//
// Tests for IfStmt
//

TEST_F(DeadCodeOptimizerTests,
IfStmtWithFloatCondEvaluatedToFalseIsOptimized) {
	// if (2.0 - 2.0) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	AddOpExpr* addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	AddOpExpr* addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	IfStmt* ifStmt(
		IfStmt::create(
			subOpExpr,
			assignStmtInIf,
			assignStmtOutIf
	));
	testFunc->setBody(ifStmt);

	optimize(module);

	AssignStmt* outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmt) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmt, assignStmtOutIf) <<
		"expected `" << assignStmtOutIf << "`, "
		"got `" << outAssignStmt << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithElseWithFloatCondEvaluatedToFalseIsOptimized) {
	// if (2.0 - 2.0) {
	//     b = 2 + 4;
	// } else {
	//     b = 2 + 4;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// b = 2 + 4;
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	AddOpExpr* addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	AddOpExpr* addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	IfStmt* ifStmt(
		IfStmt::create(
			subOpExpr,
			assignStmtInIf,
			assignStmtOutIf
	));
	ifStmt->setElseClause(assignStmtInIf);
	testFunc->setBody(ifStmt);

	optimize(module);

	AssignStmt* outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtInIf) <<
		"expected `" << assignStmtInIf << "`, "
		"got `" << outAssignStmtB << "`";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(
		outAssignStmtB->getSuccessor()));
	EXPECT_EQ(outAssignStmtA, assignStmtOutIf) <<
		"expected `" << assignStmtOutIf << "`, "
		"got `" << outAssignStmtA << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithBoolCondEvaluatedToTrueIsOptimized) {
	// if (true) {
	//     b = 2 + 4;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// b = 2 + 4;
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	AddOpExpr* addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	IfStmt* ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtInIf,
			assignStmtOutIf
	));
	testFunc->setBody(ifStmt);

	optimize(module);

	AssignStmt* outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtInIf) <<
		"expected `" << assignStmtInIf << "`, "
		"got `" << outAssignStmtB << "`";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(
		outAssignStmtB->getSuccessor()));
	EXPECT_EQ(outAssignStmtA, assignStmtOutIf) <<
		"expected `" << assignStmtOutIf << "`, "
		"got `" << outAssignStmtA << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithElseWithBoolCondEvaluatedToTrueIsOptimized) {
	// if (true) {
	//     b = 2 + 4;
	// } else {
	//     b = 2 + 4;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// b = 2 + 4;
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	AddOpExpr* addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	IfStmt* ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtInIf,
			assignStmtOutIf
	));
	ifStmt->setElseClause(assignStmtInIf);
	testFunc->setBody(ifStmt);

	optimize(module);

	AssignStmt* outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtInIf) <<
		"expected `" << assignStmtInIf << "`, "
		"got `" << outAssignStmtB << "`";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(
		outAssignStmtB->getSuccessor()));
	EXPECT_EQ(outAssignStmtA, assignStmtOutIf) <<
		"expected `" << assignStmtOutIf << "`, "
		"got `" << outAssignStmtA << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithElseIfWithBoolCondEvaluatedToTrueIsOptimized) {
	// if (true) {
	//     c = 2 + 4;
	// } else if (false) {
	//     b = 2 + 4;
	// } else if (b) {
	//     b = 2 + 4;
	// }
	//
	// Can be optimized to
	// c = 2 + 4;
	//
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	IfStmt* ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtC
	));
	ifStmt->addClause(ConstBool::create(false), assignStmtB);
	ifStmt->addClause(varB, assignStmtB);
	testFunc->setBody(ifStmt);

	optimize(module);

	AssignStmt* outAssignStmtC(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtC) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtC, assignStmtC) <<
		"expected `" << assignStmtC << "`, "
		"got `" << outAssignStmtC << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithElseIfWithNotEvaluatedCondAndOneElseIfWithEvaluatedToFalseIsOptimized) {
	// if (b + 5) {
	//     c = 2 + 4;
	// } else if (false) {
	//     b = 2 + 4;
	// } else if (c + 4) {
	//     b = 2 + 4;
	// }
	//
	// Can be optimized to
	// if (b + 5) {
	//     c = 2 + 4;
	// } else if (c + 4) {
	//     b = 2 + 4;
	// }
	//
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprBInCond(
		AddOpExpr::create(
			varB,
			ConstInt::create(5, 64)
	));
	AddOpExpr* addOpExprCInCond(
		AddOpExpr::create(
			varC,
			ConstInt::create(4, 64)
	));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	IfStmt* ifStmt(
		IfStmt::create(
			addOpExprBInCond,
			assignStmtC
	));
	ifStmt->addClause(ConstBool::create(false), assignStmtB);
	ifStmt->addClause(addOpExprCInCond, assignStmtB);
	testFunc->setBody(ifStmt);

	optimize(module);

	IfStmt* outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outIfStmt->getFirstIfCond(), addOpExprBInCond) <<
		"expected `" << addOpExprBInCond << "`, "
		"got `" << outIfStmt->getFirstIfCond() << "`";
	ASSERT_TRUE(outIfStmt->hasElseIfClauses()) <<
		"expected `Else-If clause`";
	auto it = outIfStmt->clause_begin();
	EXPECT_EQ((++it)->first, addOpExprCInCond) <<
		"expected `" << addOpExprCInCond << "`, "
		"got `" << (++it)->first << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithElseIfWithNotEvaluatedCondAndOneFirstIfWithEvaluatedToFalseIsOptimized) {
	// if (false) {
	//     c = 2 + 4;
	// } else if (b + 5) {
	//     b = 2 + 4;
	// } else if (c + 4) {
	//     b = 2 + 4;
	// }
	//
	// Can be optimized to
	// if (b + 5) {
	//     b = 2 + 4;
	// } else if (c + 4) {
	//     b = 2 + 4;
	// }
	//
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprBInCond(
		AddOpExpr::create(
			varB,
			ConstInt::create(5, 64)
	));
	AddOpExpr* addOpExprCInCond(
		AddOpExpr::create(
			varC,
			ConstInt::create(4, 64)
	));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	IfStmt* ifStmt(
		IfStmt::create(
			ConstBool::create(false),
			assignStmtC
	));
	ifStmt->addClause(addOpExprBInCond, assignStmtB);
	ifStmt->addClause(addOpExprCInCond, assignStmtB);
	testFunc->setBody(ifStmt);

	optimize(module);

	IfStmt* outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outIfStmt->getFirstIfCond(), addOpExprBInCond) <<
		"expected `" << addOpExprBInCond << "`, "
		"got `" << outIfStmt->getFirstIfCond() << "`";
	ASSERT_TRUE(outIfStmt->hasElseIfClauses()) <<
		"expected `Else-If clause`";
	auto it = outIfStmt->clause_begin();
	EXPECT_EQ((++it)->first, addOpExprCInCond) <<
		"expected `" << addOpExprCInCond << "`, "
		"got `" << (++it)->first << "`";
}

TEST_F(DeadCodeOptimizerTests,
IfStmtWithElseIfWithGotoLabelWithBoolCondEvaluatedToTrueIsOptimized) {
	// if (true) {
	//     b = 2 + 4;
	// } else if (false) {
	//     b = 2 + 4;
	// } else if (false) {
	//     label: c = 2 + 4;
	// }
	//
	// Can be optimized to
	// if (true) {
	//    b = 2 + 4;
	// } else if (false) {
	//    label: c = 2 + 4;
	// }
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	AddOpExpr* addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	GotoStmt::create(assignStmtC);
	IfStmt* ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtB
	));
	ifStmt->addClause(ConstBool::create(false), assignStmtB);
	ifStmt->addClause(ConstBool::create(false), assignStmtC);
	testFunc->setBody(ifStmt);

	optimize(module);

	IfStmt* outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
	ASSERT_TRUE(outIfStmt->hasElseIfClauses()) <<
		"expected `Else-If clause`";
	auto it = outIfStmt->clause_begin();
	ConstBool* outConstBool(cast<ConstBool>((++it)->first));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << (++it)->first << "`";
	EXPECT_EQ(outConstBool->getValue(), false) <<
		"expected `False`, "
		"got `" << outConstBool << "`";
}

//
// Tests for SwitchStmt
//

TEST_F(DeadCodeOptimizerTests,
SwitchStmtOneClauseWithConditionEqualToControlExprIsOptimized) {
	// switch (2) {
	//     case 2: b = 2 + 4;
	//             break;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// b = 2 + 4;
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	BreakStmt* breakStmt(BreakStmt::create());
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			breakStmt
	));
	AddOpExpr* addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	SwitchStmt* switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	testFunc->setBody(switchStmt);

	optimize(module);

	AssignStmt* outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtB) <<
		"expected `" << assignStmtB << "`, "
		"got `" << outAssignStmtB << "`";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(
		outAssignStmtB->getSuccessor()));
	EXPECT_EQ(outAssignStmtA, assignStmtA) <<
		"expected `" << assignStmtA << "`, "
		"got `" << outAssignStmtA << "`";
}

TEST_F(DeadCodeOptimizerTests,
SwitchStmtOneClauseWithConditionEqualToControlExprWithoutBreakNotOptimized) {
	// switch (2) {
	//     case 2: b = 2 + 4;
	// }
	// a = 1 + 3;
	//
	// Not optimized because clause doesn't have break, continue, or return
	// statement at last statement. Optimization now supported only clauses with
	// break, continue or return statement on last statement.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch
	));
	AddOpExpr* addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	SwitchStmt* switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	testFunc->setBody(switchStmt);

	optimize(module);

	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected `SwitchStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(DeadCodeOptimizerTests,
SwitchStmtWithClauseThatContainsGotoLabelIsOptimized) {
	// switch (2) {
	//     case 2: b = 2 + 4;
	//             break;
	//     case 8: b = 2 + 4;
	//             break;
	//     case 4: label: c = 2 + 4;
	//             break;
	// }
	//
	// Optimized to
	// switch (2) {
	//     case 2: b = 2 + 4;
	//             break;
	//     case 4: label: c = 2 + 4;
	//             break;
	// }
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	BreakStmt* breakStmt(BreakStmt::create());
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			breakStmt
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprInSwitch,
			breakStmt
	));
	GotoStmt::create(assignStmtC);
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(2, 64)));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	switchStmt->addClause(ConstInt::create(8, 64), assignStmtB);
	switchStmt->addClause(ConstInt::create(4, 64), assignStmtC);
	testFunc->setBody(switchStmt);

	optimize(module);

	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected `SwitchStmt`, "
		"got `" << testFunc->getBody() << "`";
	auto it = outSwitchStmt->clause_begin();
	ConstInt* outConstInt(cast<ConstInt>((++it)->first));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << (++it)->first << "`";
	ConstInt* result(ConstInt::create(4, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(DeadCodeOptimizerTests,
SwitchStmtWithDefaultClauseWhichContainsGotoLabelNotOptimized) {
	// switch (2) {
	//     case 2:  b = 2 + 4;
	//              return 2;
	//     default: label: c = 2 + 4;
	//              continue;
	// }
	// a = 1 + 3;
	//
	// Not optimized. Output must be same as input due to default which contains
	// goto label.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			ReturnStmt::create(ConstInt::create(2, 64))
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprInSwitch,
			ContinueStmt::create()
	));
	GotoStmt::create(assignStmtC);
	AddOpExpr* addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	SwitchStmt* switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	switchStmt->addDefaultClause(assignStmtC);
	testFunc->setBody(switchStmt);

	optimize(module);

	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected `SwitchStmt`, "
		"got `" << testFunc->getBody() << "`";
	auto it = outSwitchStmt->clause_begin();
	ConstInt* outConstInt(cast<ConstInt>(it->first));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << it->first << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
	ASSERT_TRUE(outSwitchStmt->hasDefaultClause()) <<
		"expected `Default clause`";
}

TEST_F(DeadCodeOptimizerTests,
SwitchStmtWithDefaultClauseFirstClauseContainsReturnIsOptimized) {
	// switch (2) {
	//     case 2:  b = 2 + 4;
	//              return 2;
	//     default: c = 2 + 4;
	//              continue;
	// }
	// a = 1 + 3;
	//
	// Can be optimized to
	// b = 2 + 4;
	// return 2;
	// a = 1 + 3;
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	ReturnStmt* returnStmt(ReturnStmt::create(ConstInt::create(2, 64)));
	AddOpExpr* addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	AssignStmt* assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			returnStmt
	));
	AssignStmt* assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprInSwitch,
			ContinueStmt::create()
	));
	AddOpExpr* addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	AssignStmt* assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	SwitchStmt* switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	switchStmt->addDefaultClause(assignStmtC);
	testFunc->setBody(switchStmt);

	optimize(module);

	AssignStmt* outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtB) <<
		"expected `" << assignStmtB << "`, "
		"got `" << outAssignStmtB << "`";
	ReturnStmt* outReturnStmt(cast<ReturnStmt>(
		outAssignStmtB->getSuccessor()));
	ASSERT_TRUE(outReturnStmt) <<
		"expected `ReturnStmt`, "
		"got `" << outAssignStmtB->getSuccessor() << "`";
	EXPECT_EQ(outReturnStmt, returnStmt) <<
		"expected `" << returnStmt << "`, "
		"got `" << outReturnStmt << "`";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(
		outReturnStmt->getSuccessor()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected `AssignStmt`, "
		"got `" << outReturnStmt->getSuccessor() << "`";
	EXPECT_EQ(outAssignStmtA, assignStmtA) <<
		"expected `" << assignStmtA << "`, "
		"got `" << outAssignStmtA << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
