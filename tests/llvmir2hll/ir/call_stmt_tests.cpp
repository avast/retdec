/*
* @file tests/llvmir2hll/ir/call_stmt_tests.cpp
* @brief Tests for the @c call_stmt module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c call_stmt module.
*/
class CallStmtTests: public Test {};

//
// asExpression()
//

TEST_F(CallStmtTests,
AsExpressionReturnsCorrectExpression) {
	auto callExpr = CallExpr::create(
		Variable::create("func", IntType::create(32))
	);
	auto callStmt = CallStmt::create(callExpr);

	auto asExpr = callStmt->asExpression();

	auto asCallExpr = cast<CallExpr>(asExpr);
	ASSERT_TRUE(asCallExpr);
	ASSERT_BIR_EQ(callExpr, asCallExpr);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
