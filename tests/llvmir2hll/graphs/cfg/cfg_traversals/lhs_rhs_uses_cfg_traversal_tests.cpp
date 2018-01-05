/**
* @file tests/llvmir2hll/graphs/cfg/cfg_traversals/lhs_rhs_uses_cfg_traversal_tests.cpp
* @brief Tests for the @c lhs_rhs_uses_cfg_traversal module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/lhs_rhs_uses_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c lhs_rhs_uses_cfg_traversal module.
*/
class LhsRhsUsesCFGTraversalTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		cfgBuilder = NonRecursiveCFGBuilder::create();
	}

protected:
	ShPtr<CFGBuilder> cfgBuilder;
};

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesForVarDefStmtWithNoInitializer) {
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

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(varDefA,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenStmtIsNotInCFG) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(varDefA,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesForNonAssignOrVarDefStmt) {
	// Set-up the module.
	//
	// void test() {
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	testFunc->setBody(returnA);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(returnA,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesForAssignStmtWhereLhsIsNotVariable) {
	// Set-up the module.
	//
	// void test() {
	//    a[1] = b;
	//    return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32))); // the type does not matter
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignA1B(AssignStmt::create(
		ArrayIndexOpExpr::create(varA, ConstInt::create(1, 32)), varB, returnA));
	testFunc->setBody(assignA1B);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignA1B,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesForAssignStmtWhereRhsContainsDereference) {
	// Set-up the module.
	//
	// void test() {
	//    a = *b;
	//    return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32))); // the type does not matter
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, DerefOpExpr::create(varB), returnA));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenLhsMayBeUsedIndirectly) {
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

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varB))
		.WillByDefault(Return(false));
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenRhsMayBeUsedIndirectly) {
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

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(false));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varB))
		.WillByDefault(Return(true));
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
SingleUseRightAfterOriginalStatement) {
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

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(returnA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
SingleUseRightAfterOriginalStatementRhsHasNoVariables) {
	// Set-up the module.
	//
	// void test() {
	//     a = 1;
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32), returnA));
	testFunc->setBody(assignA1);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignA1,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(returnA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenRhsModifiedBeforeLhsUse) {
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
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32), returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignB1));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenLhsModifiedBeforeItIsUsed) {
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
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32), returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignA1));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenLhsIsModifiedAfterItIsUsed) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     c = a;
	//     a = 1;
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
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32), returnA));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA, assignA1));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignCA));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
TwoUsesRightAfterOriginalStatement) {
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

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(assignCA);
	refUses.insert(returnA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
RhsModifiedAfterTheOnlyUseOfLhsAndFuncReturnsRightAfterThat) {
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

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(assignCA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
RhsModifiedAfterTheOnlyUseOfLhsAndFuncReturnsAfterMoreStmtsNoLhsUses) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     c = a;
	//     b = 1;
	//     c = 1; // auxiliary statement
	//     c = 2; // auxiliary statement
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignC2(AssignStmt::create(varC, ConstInt::create(2, 32)));
	ShPtr<AssignStmt> assignC1(AssignStmt::create(varC, ConstInt::create(1, 32), assignC2));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32), assignC1));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA, assignB1));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignCA));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(assignCA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesRhsModifiedAfterTheOnlyUseOfLhsAndFuncReturnsAfterMoreStmtsButLhsIsUsed) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     c = a;
	//     b = 1;
	//     c = a; // use of `a` after `b` has been written to
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignCA1(AssignStmt::create(varC, varA));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32), assignCA1));
	ShPtr<AssignStmt> assignCA2(AssignStmt::create(varC, varA, assignB1));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignCA2));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenRhsModifiedAfterTheOnlyUseOfLhsAndFuncNoReturnAtEndOfNode) {
	// Set-up the module.
	//
	// void test() {
	//     if (1) {
	//         a = b;
	//         c = a;
	//         b = 1;
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
	ShPtr<AssignStmt> assignCA2(AssignStmt::create(varC, varA));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32)));
	ShPtr<AssignStmt> assignCA1(AssignStmt::create(varC, varA, assignB1));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, assignCA1));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignAB, assignCA2));
	testFunc->setBody(ifStmt);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenLhsIsAssignedValueInIfStmt) {
	// Set-up the module.
	//
	// void test() {
	//     a = 1;     // <-- start
	//     if (1) {
	//         a = b;
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
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignAB, assignCA));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32), ifStmt));
	testFunc->setBody(assignA1);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignA1,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
LhsIsAssignedValueOutsideIfStmt) {
	// Set-up the module.
	//
	// void test() {
	//     a = 1;
	//     if (1) {
	//         a = b; // <-- start
	//     }
	//     c = a;     // we have to mark this as a use of `a` in `a = b`
	//                // because in this situation, we have no information
	//                // about `a = 1`
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignAB, assignCA));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32), ifStmt));
	testFunc->setBody(assignA1);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(assignCA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
FunctionCallAfterOrigStmtThatDoesNotModifyLhsOrRhs) {
	// Set-up the module.
	//
	// void test() {
	//     a = b;
	//     rand();
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<Variable> varRand(Variable::create("a", IntType::create(16)));
	ShPtr<CallStmt> randCall(CallStmt::create(CallExpr::create(varRand), returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, randCall));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	refUses.insert(returnA);
	ASSERT_EQ(refUses, uses);
}

TEST_F(LhsRhsUsesCFGTraversalTests,
NoUsesWhenThereIsFunctionCallAfterOrigStmtThatModifiesRhs) {
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
	ShPtr<CallStmt> setBCall(CallStmt::create(CallExpr::create(setB->getAsVar()), returnA));
	ShPtr<AssignStmt> assignAB(AssignStmt::create(varA, varB, setBCall));
	testFunc->setBody(assignAB);

	// Instantiate the needed analyses.
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ShPtr<CallInfoObtainer> cio(OptimCallInfoObtainer::create());
	cio->init(CGBuilder::getCG(module), va);

	// Perform the traversal.
	StmtSet uses(LhsRhsUsesCFGTraversal::getUses(assignAB,
		cfgBuilder->getCFG(testFunc), va, cio));

	// Check the result.
	StmtSet refUses;
	ASSERT_EQ(refUses, uses);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
