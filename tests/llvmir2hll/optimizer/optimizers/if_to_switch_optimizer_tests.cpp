/**
* @file tests/llvmir2hll/optimizer/optimizers/if_to_switch_optimizer_tests.cpp
* @brief Tests for the @c if_to_switch_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_to_switch_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c if_to_switch_optimizer module.
*/
class IfToSwitchOptimizerTests: public TestsWithModule {
protected:
	void checkCorrectConvertIfToSwitch(ShPtr<IfStmt> ifStmt, ShPtr<Statement>
		stmt, bool isBreakNeeded);
};

/**
* @brief Check if @a ifStmt was correctly transformed to @c SwitchStmt.
*
* @param[in] ifStmt If statement to check.
* @param[in] stmt Optimized statement to compare.
* @param[in] isBreakNeeded Set control to if break is in case clauses needed.
*/
void IfToSwitchOptimizerTests::checkCorrectConvertIfToSwitch(ShPtr<IfStmt> ifStmt,
		ShPtr<Statement> stmt, bool isBreakNeeded) {
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(stmt));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected `SwitchStmt`, "
		"got `" << ifStmt << "`";

	// Check control expression.
	ShPtr<EqOpExpr> eqOpExpr(cast<EqOpExpr>(ifStmt->getFirstIfCond()));
	ShPtr<Expression> controlExpr;
	if (isa<ConstInt>(eqOpExpr->getFirstOperand())) {
		controlExpr = eqOpExpr->getSecondOperand();
	} else {
		controlExpr = eqOpExpr->getFirstOperand();
	}
	ASSERT_EQ(controlExpr, outSwitchStmt->getControlExpr()) <<
		"expected `" << controlExpr << "`, "
		"got `" << outSwitchStmt->getControlExpr() << "`";

	// Check correctness transform if clauses to switch clauses.
	auto switchIt = outSwitchStmt->clause_begin();
	for (auto i = ifStmt->clause_begin(), e = ifStmt->clause_end(); i != e; ++i) {
		ShPtr<EqOpExpr> eqOpExpr(cast<EqOpExpr>(i->first));
		ShPtr<ConstInt> constant(cast<ConstInt>(eqOpExpr->getFirstOperand()));
		if (!constant) {
			constant = cast<ConstInt>(eqOpExpr->getSecondOperand());
		}
		ASSERT_EQ(constant, switchIt->first) <<
			"expected `" << constant << "`, "
			"got `" << switchIt->first << "`";

		ShPtr<BreakStmt> outBreakStmt(cast<BreakStmt>(Statement::
			getLastStatement(i->second)));
		if (isBreakNeeded) {
			ASSERT_TRUE(outBreakStmt) <<
				"expected `BreakStmt`";
		} else {
			ASSERT_FALSE(outBreakStmt) <<
				"not expected `BreakStmt`";
		}
		switchIt++;
	}

	if (ifStmt->hasElseClause()) {
		// Check correctness transform of else clause.
		ASSERT_TRUE(outSwitchStmt->hasDefaultClause()) <<
			"expected that `" << outSwitchStmt <<
			"` has default clause";
		ShPtr<BreakStmt> outBreakStmt(cast<BreakStmt>(Statement::getLastStatement(
			outSwitchStmt->getDefaultClauseBody())));
		ASSERT_TRUE(outBreakStmt) <<
			"expected `BreakStmt`";
	}
}

TEST_F(IfToSwitchOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<IfToSwitchOptimizer> optimizer(new IfToSwitchOptimizer(module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(IfToSwitchOptimizerTests,
NotSameControlExprInElseIfClausesNotOptimize) {
	// if (a == 5) {
	//     b = b + 3;
	// } else if (b + 3 == 6) {
	//     b = b + 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
OnlyIfConditionNotOptimize) {
	// if (a == 5) {
	//     b = b + 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SameControlExprButNoEqOpExprNotOptimize) {
	// if (b + 3) {
	//     b = b + 3;
	// } else if (b + 3) {
	//     b = b + 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(addOpExpr, assignStmt));
	ifStmt->addClause(addOpExpr, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SameControlExprButNotConstIntOperandNotOptimize) {
	// if (a == a) {
	//     b = b + 3;
	// } else if (b + 3 == b) {
	//     b = b + 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			varA,
			varA
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			varB
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SameControlExprButBreakInIfStmtNotOptimize) {
	// if (b + 3 == 2) {
	//     break;
	// } else if (b + 3 == 3) {
	//     b = b + 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(2, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, BreakStmt::create()));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SameControlExprInElseIfClausesButDerefOpExprInControlExprNotOptimize) {
	// if (*a == 5) {
	//     a = 3;
	// } else if (*a == 6) {
	//     a = 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(varA));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			derefOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			derefOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			ConstInt::create(3, 64)
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SameControlExprInElseIfClausesButArrayIndexOpExprInControlExprNotOptimize) {
	// if (a[3] == 5) {
	//     a = 3;
	// } else if (a[3] == 6) {
	//     a = 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(ArrayIndexOpExpr::create(varA,
		ConstInt::create(3, 64)));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			arrayIndexOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			arrayIndexOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			ConstInt::create(3, 64)
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SameControlExprInElseIfClausesButFunctionCallInControlExprNotOptimize) {
	// if (func() == 5) {
	//     a = 3;
	// } else if (func() == 6) {
	//     a = 3;
	// }
	//
	// Not optimized
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ExprVector args;
	args.push_back(varA);
	ShPtr<CallExpr> callExpr(CallExpr::create(varA, args));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(ArrayIndexOpExpr::create(varA,
		ConstInt::create(3, 64)));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			callExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			callExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			ConstInt::create(3, 64)
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected `IfStmt`, "
		"got `" << testFunc->getBody() << "`";
}

TEST_F(IfToSwitchOptimizerTests,
SimpleSubstituteIfToSwitchOptimize) {
	// if (b + 3 == 5) {
	//     b = b + 3;
	// } else if (b + 3 == 6) {
	//     b = b + 3;
	// }
	//
	// Optimized to:
	// switch(b + 3) {
	//     case 5: b = b + 3; break;
	//     case 6: b = b + 3; break;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<AddOpExpr> addOpExpr2(
		AddOpExpr::create(
			varB,
			ConstInt::create(4, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<AssignStmt> assignStmt2(
		AssignStmt::create(
			varB,
			addOpExpr2
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt2);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	checkCorrectConvertIfToSwitch(ifStmt, testFunc->getBody(), true);
}

TEST_F(IfToSwitchOptimizerTests,
MoreComplicatedSubstituteIfToSwitchOptimize) {
	// if (b + 3 == 5) {
	// } else if (b + 3 == 6) {
	//     b = b + 3;
	// } else if (b + 3 == 8) {
	//     b = b + 3;
	// } else if (b + 3 == 12) {
	//     b = b + 3;
	// }
	//
	// Optimized to:
	// switch(b + 3) {
	//     case 5: b = b + 3; break;
	//     case 6: b = b + 3; break;
	//     case 8: b = b + 3; break;
	//     case 12: b = b + 3; break;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf1(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf2(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(8, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf3(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(12, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf1, assignStmt);
	ifStmt->addClause(eqOpExprElseIf2, assignStmt);
	ifStmt->addClause(eqOpExprElseIf3, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	checkCorrectConvertIfToSwitch(ifStmt, testFunc->getBody(), true);
}

TEST_F(IfToSwitchOptimizerTests,
SimpleSubstituteIfToSwitchWithElseClauseOptimize) {
	// if (b + 3 == 5) {
	//     b = b + 3;
	// } else if (b + 3 == 6) {
	//     b = b + 3;
	// } else {
	//     b = b + 3;
	// }
	//
	// Optimized to:
	// switch(b + 3) {
	//     case 5: b = b + 3; break;
	//     case 6: b = b + 3; break;
	//     default: b = b + 3; break;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	ifStmt->setElseClause(assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	checkCorrectConvertIfToSwitch(ifStmt, testFunc->getBody(), true);
}

TEST_F(IfToSwitchOptimizerTests,
SimpleSubstituteIfToSwitchControlExprIsOnNotSameSidesOptimize) {
	// if (b + 3 == 5) {
	//     b = b + 3;
	// } else if (6 == b + 3) {
	//     b = b + 3;
	// }
	//
	// Optimized to:
	// switch(b + 3) {
	//     case 5: b = b + 3; break;
	//     case 6: b = b + 3; break;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			ConstInt::create(6, 64),
			addOpExpr
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varB,
			addOpExpr
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, assignStmt));
	ifStmt->addClause(eqOpExprElseIf, assignStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	checkCorrectConvertIfToSwitch(ifStmt, testFunc->getBody(), true);
}

TEST_F(IfToSwitchOptimizerTests,
SimpleSubstituteIfToSwitchLastStmtIsReturnStmtOptimize) {
	// if (b + 3 == 5) {
	//     return 2;
	// } else if (b + 3 == 6) {
	//     return 2;
	// }
	//
	// Optimized to:
	// switch(b + 3) {
	//     case 5: return 2;
	//     case 6: return 2;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(ConstInt::create(2, 64)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, returnStmt));
	ifStmt->addClause(eqOpExprElseIf, returnStmt);
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	checkCorrectConvertIfToSwitch(ifStmt, testFunc->getBody(), false);
}

TEST_F(IfToSwitchOptimizerTests,
SimpleSubstituteIfToSwitchLastStmtIsContinueStmtOptimize) {
	// if (b + 3 == 5) {
	//     continue;
	// } else if (b + 3 == 6) {
	//     continue;
	// }
	//
	// Optimized to:
	// switch(b + 3) {
	//     case 5: continue;
	//     case 6: continue;
	// }
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			ConstInt::create(3, 64)
	));
	ShPtr<EqOpExpr> eqOpExprIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<EqOpExpr> eqOpExprElseIf(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<IfStmt> ifStmt(IfStmt::create(eqOpExprIf, ContinueStmt::create()));
	ifStmt->addClause(eqOpExprElseIf, ContinueStmt::create());
	testFunc->setBody(ifStmt);

	// Optimize the module.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<IfToSwitchOptimizer>(module, va);

	checkCorrectConvertIfToSwitch(ifStmt, testFunc->getBody(), false);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
