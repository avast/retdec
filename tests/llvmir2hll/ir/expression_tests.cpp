/**
* @file tests/llvmir2hll/ir/expression_tests.cpp
* @brief Tests for the @c expression module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c expression module.
*/
class ExpressionTests: public TestsWithModule {};

//
// replaceExpression()
//

TEST_F(ExpressionTests,
ExpressionInAnotherExpressionIsCorrectlyReplaced) {
	// Setup.
	//
	// a = a + b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	ShPtr<AddOpExpr> addAB(AddOpExpr::create(varA, varB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, addAB));

	// Perform the replacement.
	Expression::replaceExpression(varB, varC);

	// Check that the output is correct.
	//
	// a = a + c
	//
	EXPECT_EQ(varA, addAB->getFirstOperand()) <<
		"expected `" << varA->getName() << "`, but got `" <<
		addAB->getFirstOperand() << "`";
	EXPECT_EQ(varC, addAB->getSecondOperand()) <<
		"expected `" << varC->getName() << "`, but got `" <<
		addAB->getSecondOperand() << "`";
}

TEST_F(ExpressionTests,
ExpressionOnTheRightHandSideOfVarDefStmtIsCorrectlyReplaced) {
	// Setup.
	//
	// a = b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, varB));

	// Perform the replacement.
	Expression::replaceExpression(varB, varC);

	// Check that the output is correct.
	//
	// a = c
	//
	EXPECT_EQ(varA, varDefA->getVar()) <<
		"expected `" << varA->getName() << "`, but got `" <<
		varDefA->getVar() << "`";
	EXPECT_EQ(varC, varDefA->getInitializer()) <<
		"expected `" << varC->getName() << "`, but got `" <<
		varDefA->getInitializer() << "`";
}

TEST_F(ExpressionTests,
ExpressionOnTheRightHandSideOfGlobalVariableDefinitionIsCorrectlyReplaced) {
	// Setup.
	//
	// a = b (global variable definition)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	module->addGlobalVar(varA, varB);

	// Perform the replacement.
	Expression::replaceExpression(varB, varC);

	// Check that the output is correct.
	//
	// a = c
	//
	EXPECT_EQ(varC, module->getInitForGlobalVar(varA)) <<
		"expected `" << varC->getName() << "`, but got `" <<
		module->getInitForGlobalVar(varA) << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
