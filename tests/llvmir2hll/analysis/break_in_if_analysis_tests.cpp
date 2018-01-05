/**
* @file tests/llvmir2hll/analysis/break_in_if_analysis_tests.cpp
* @brief Tests for the @c break_in_if_analysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/break_in_if_analysis.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c break_in_if_analysis module.
*/
class BreakInIfAnalysisTests: public TestsWithModule {};

TEST_F(BreakInIfAnalysisTests,
BreakInNestedStatement) {
	// Set-up the module.
	//
	// void test() {
	//   int a;
	//   int b;
	//   if (5) {
	//       a = 1;
	//   } else {
	//       break;
	//   }
	//   b = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32)));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(5, 64), assignA1));
	ifStmt->setElseClause(breakStmt);
	ShPtr<AssignStmt> assignB(AssignStmt::create(varB, ConstInt::create(1, 32)));
	varDefA->setSuccessor(varDefB);
	varDefB->setSuccessor(ifStmt);
	ifStmt->setSuccessor(assignB);

	testFunc->setBody(varDefA);

	// Check the result of hasBreakStmt().
	EXPECT_TRUE(BreakInIfAnalysis::hasBreakStmt(ifStmt));
}

TEST_F(BreakInIfAnalysisTests,
BreakInNestedInNestedStatement) {
	// Set-up the module.
	//
	// void test() {
	//   int a;
	//   int b;
	//   if (5) {
	//       a = 1;
	//       while (2) {
	//           break;
	//       }
	//   }
	//   b = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32)));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(5, 64), assignA1));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(ConstInt::create(
		2, 64), breakStmt));
	ShPtr<AssignStmt> assignB(AssignStmt::create(varB, ConstInt::create(1, 32)));
	varDefA->setSuccessor(varDefB);
	varDefB->setSuccessor(ifStmt);
	assignA1->setSuccessor(whileLoopStmt);
	ifStmt->setSuccessor(assignB);

	testFunc->setBody(varDefA);

	// Check the result of hasBreakStmt().
	EXPECT_TRUE(BreakInIfAnalysis::hasBreakStmt(ifStmt));
}

TEST_F(BreakInIfAnalysisTests,
BreakOutOfNestedStatements) {
	// Set-up the module.
	//
	// void test() {
	//   int b;
	//   if (5) {
	//       b = 1;
	//   }
	//   break;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(5, 64), assignB1));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	varDefB->setSuccessor(ifStmt);
	ifStmt->setSuccessor(breakStmt);

	testFunc->setBody(varDefB);

	// Check the result of hasBreakStmt().
	EXPECT_FALSE(BreakInIfAnalysis::hasBreakStmt(ifStmt));
}

TEST_F(BreakInIfAnalysisTests,
BreakOutOfNestedStatementsAndWithGotoThatReferenceOutOfIfStatementBody) {
	// Set-up the module.
	//
	// void test() {
	//   int b;
	//   if (5) {
	//       b = 1;
	//       lab;
	//   }
	//   lab: b = b + 2;
	//   break;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32)));
	ShPtr<AssignStmt> assignB2(AssignStmt::create(varB, ConstInt::create(2, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(5, 64), assignB1));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(assignB2));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	varDefB->setSuccessor(ifStmt);
	assignB1->setSuccessor(gotoStmt);
	ifStmt->setSuccessor(breakStmt);

	testFunc->setBody(varDefB);

	// Check the result of hasBreakStmt().
	EXPECT_FALSE(BreakInIfAnalysis::hasBreakStmt(ifStmt));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
