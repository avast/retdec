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
	void optimize(ShPtr<Module> module);
};

void DeadCodeOptimizerTests::optimize(ShPtr<Module> module) {
	ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
		create());
	Optimizer::optimize<DeadCodeOptimizer>(module, evaluator);
}

TEST_F(DeadCodeOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
		create());
	ShPtr<DeadCodeOptimizer> optimizer(
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	ShPtr<ForLoopStmt> forLoopStmt(
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

	ShPtr<AssignStmt> outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	ShPtr<ForLoopStmt> forLoopStmt(
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

	ShPtr<AssignStmt> outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	GotoStmt::create(assignStmtB);
	ShPtr<ForLoopStmt> forLoopStmt(
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

	ShPtr<ForLoopStmt> outForLoopStmt(cast<ForLoopStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	ShPtr<AddOpExpr> addOpExprEndCond(
		AddOpExpr::create(
			varA,
			varI
	));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			addOpExprEndCond,
			ConstInt::create(4, 64)
	));
	ShPtr<ForLoopStmt> forLoopStmt(
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

	ShPtr<ForLoopStmt> outForLoopStmt(cast<ForLoopStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprA(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprA
	));
	ShPtr<GtOpExpr> ltOpExpr(
		GtOpExpr::create(
			varI,
			ConstInt::create(4, 64)
	));
	ShPtr<ForLoopStmt> forLoopStmt(
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

	ShPtr<ForLoopStmt> outForLoopStmt(cast<ForLoopStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInWhile(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtInWhile(
		AssignStmt::create(
			varB,
			addOpExprInWhile
	));
	ShPtr<AddOpExpr> addOpExprOutWhile(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtOutWhile(
		AssignStmt::create(
			varA,
			addOpExprOutWhile
	));
	ShPtr<WhileLoopStmt> whileLoopStmt(
		WhileLoopStmt::create(
			ConstBool::create(false),
			assignStmtInWhile,
			assignStmtOutWhile
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	ShPtr<AddOpExpr> addOpExprInWhile(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtInWhile(
		AssignStmt::create(
			varB,
			addOpExprInWhile
	));
	ShPtr<AddOpExpr> addOpExprOutWhile(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtOutWhile(
		AssignStmt::create(
			varA,
			addOpExprOutWhile
	));
	ShPtr<WhileLoopStmt> whileLoopStmt(
		WhileLoopStmt::create(
			subOpExpr,
			assignStmtInWhile,
			assignStmtOutWhile
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<WhileLoopStmt> whileLoopStmt(
		WhileLoopStmt::create(
			ConstBool::create(true),
			assignStmt
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	ShPtr<WhileLoopStmt> outWhileLoopStmt(cast<WhileLoopStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	GotoStmt::create(assignStmt);
	ShPtr<WhileLoopStmt> whileLoopStmt(
		WhileLoopStmt::create(
			ConstBool::create(true),
			assignStmt
	));
	testFunc->setBody(whileLoopStmt);

	optimize(module);

	ShPtr<WhileLoopStmt> outWhileLoopStmt(cast<WhileLoopStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	ShPtr<AddOpExpr> addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	ShPtr<AddOpExpr> addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			subOpExpr,
			assignStmtInIf,
			assignStmtOutIf
	));
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmt(cast<AssignStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	ShPtr<AddOpExpr> addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	ShPtr<AddOpExpr> addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			subOpExpr,
			assignStmtInIf,
			assignStmtOutIf
	));
	ifStmt->setElseClause(assignStmtInIf);
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtInIf) <<
		"expected `" << assignStmtInIf << "`, "
		"got `" << outAssignStmtB << "`";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	ShPtr<AddOpExpr> addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtInIf,
			assignStmtOutIf
	));
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtInIf) <<
		"expected `" << assignStmtInIf << "`, "
		"got `" << outAssignStmtB << "`";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInIf(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtInIf(
		AssignStmt::create(
			varB,
			addOpExprInIf
	));
	ShPtr<AddOpExpr> addOpExprOutIf(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtOutIf(
		AssignStmt::create(
			varA,
			addOpExprOutIf
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtInIf,
			assignStmtOutIf
	));
	ifStmt->setElseClause(assignStmtInIf);
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtInIf) <<
		"expected `" << assignStmtInIf << "`, "
		"got `" << outAssignStmtB << "`";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtC
	));
	ifStmt->addClause(ConstBool::create(false), assignStmtB);
	ifStmt->addClause(varB, assignStmtB);
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmtC(cast<AssignStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprBInCond(
		AddOpExpr::create(
			varB,
			ConstInt::create(5, 64)
	));
	ShPtr<AddOpExpr> addOpExprCInCond(
		AddOpExpr::create(
			varC,
			ConstInt::create(4, 64)
	));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			addOpExprBInCond,
			assignStmtC
	));
	ifStmt->addClause(ConstBool::create(false), assignStmtB);
	ifStmt->addClause(addOpExprCInCond, assignStmtB);
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprBInCond(
		AddOpExpr::create(
			varB,
			ConstInt::create(5, 64)
	));
	ShPtr<AddOpExpr> addOpExprCInCond(
		AddOpExpr::create(
			varC,
			ConstInt::create(4, 64)
	));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			ConstBool::create(false),
			assignStmtC
	));
	ifStmt->addClause(addOpExprBInCond, assignStmtB);
	ifStmt->addClause(addOpExprCInCond, assignStmtB);
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprB(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprB
	));
	ShPtr<AddOpExpr> addOpExprC(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprC
	));
	GotoStmt::create(assignStmtC);
	ShPtr<IfStmt> ifStmt(
		IfStmt::create(
			ConstBool::create(true),
			assignStmtB
	));
	ifStmt->addClause(ConstBool::create(false), assignStmtB);
	ifStmt->addClause(ConstBool::create(false), assignStmtC);
	testFunc->setBody(ifStmt);

	optimize(module);

	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
	ASSERT_TRUE(outIfStmt->hasElseIfClauses()) <<
		"expected `Else-If clause`";
	auto it = outIfStmt->clause_begin();
	ShPtr<ConstBool> outConstBool(cast<ConstBool>((++it)->first));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			breakStmt
	));
	ShPtr<AddOpExpr> addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	ShPtr<SwitchStmt> switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	testFunc->setBody(switchStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtB) <<
		"expected `" << assignStmtB << "`, "
		"got `" << outAssignStmtB << "`";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch
	));
	ShPtr<AddOpExpr> addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	ShPtr<SwitchStmt> switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	testFunc->setBody(switchStmt);

	optimize(module);

	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			breakStmt
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprInSwitch,
			breakStmt
	));
	GotoStmt::create(assignStmtC);
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(2, 64)));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	switchStmt->addClause(ConstInt::create(8, 64), assignStmtB);
	switchStmt->addClause(ConstInt::create(4, 64), assignStmtC);
	testFunc->setBody(switchStmt);

	optimize(module);

	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected `SwitchStmt`, "
		"got `" << testFunc->getBody() << "`";
	auto it = outSwitchStmt->clause_begin();
	ShPtr<ConstInt> outConstInt(cast<ConstInt>((++it)->first));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << (++it)->first << "`";
	ShPtr<ConstInt> result(ConstInt::create(4, 64));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			ReturnStmt::create(ConstInt::create(2, 64))
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprInSwitch,
			ContinueStmt::create()
	));
	GotoStmt::create(assignStmtC);
	ShPtr<AddOpExpr> addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	ShPtr<SwitchStmt> switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	switchStmt->addDefaultClause(assignStmtC);
	testFunc->setBody(switchStmt);

	optimize(module);

	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected `SwitchStmt`, "
		"got `" << testFunc->getBody() << "`";
	auto it = outSwitchStmt->clause_begin();
	ShPtr<ConstInt> outConstInt(cast<ConstInt>(it->first));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << it->first << "`";
	ShPtr<ConstInt> result(ConstInt::create(2, 64));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(ConstInt::create(2, 64)));
	ShPtr<AddOpExpr> addOpExprInSwitch(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(4, 64)
	));
	ShPtr<AssignStmt> assignStmtB(
		AssignStmt::create(
			varB,
			addOpExprInSwitch,
			returnStmt
	));
	ShPtr<AssignStmt> assignStmtC(
		AssignStmt::create(
			varC,
			addOpExprInSwitch,
			ContinueStmt::create()
	));
	ShPtr<AddOpExpr> addOpExprOutSwitch(
		AddOpExpr::create(
			ConstInt::create(1, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmtA(
		AssignStmt::create(
			varA,
			addOpExprOutSwitch
	));
	ShPtr<SwitchStmt> switchStmt(
		SwitchStmt::create(
			ConstInt::create(2, 64),
			assignStmtA
	));
	switchStmt->addClause(ConstInt::create(2, 64), assignStmtB);
	switchStmt->addDefaultClause(assignStmtC);
	testFunc->setBody(switchStmt);

	optimize(module);

	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected `AssignStmt`, "
		"got `" << testFunc->getBody() << "`";
	EXPECT_EQ(outAssignStmtB, assignStmtB) <<
		"expected `" << assignStmtB << "`, "
		"got `" << outAssignStmtB << "`";
	ShPtr<ReturnStmt> outReturnStmt(cast<ReturnStmt>(
		outAssignStmtB->getSuccessor()));
	ASSERT_TRUE(outReturnStmt) <<
		"expected `ReturnStmt`, "
		"got `" << outAssignStmtB->getSuccessor() << "`";
	EXPECT_EQ(outReturnStmt, returnStmt) <<
		"expected `" << returnStmt << "`, "
		"got `" << outReturnStmt << "`";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(
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
