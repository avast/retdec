/*
* @file tests/llvmir2hll/ir/assign_stmt_tests.cpp
* @brief Tests for the @c assign_stmt module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c assign_stmt module.
*/
class AssignStmtTests: public Test {};

//
// asExpression()
//

TEST_F(AssignStmtTests,
AsExpressionReturnsCorrectExpression) {
	auto lhs = Variable::create("a", IntType::create(32));
	auto rhs = ConstInt::create(1, 3);
	auto assignStmt = AssignStmt::create(lhs, rhs);

	auto asExpr = assignStmt->asExpression();

	auto asAssignExpr = cast<AssignOpExpr>(asExpr);
	ASSERT_TRUE(asAssignExpr);
	ASSERT_BIR_EQ(lhs, asAssignExpr->getFirstOperand());
	ASSERT_BIR_EQ(rhs, asAssignExpr->getSecondOperand());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
