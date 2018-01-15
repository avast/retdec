/**
* @file tests/llvmir2hll/ir/call_expr_tests.cpp
* @brief Tests for the @c call_expr module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c call_expr module.
*/
class CallExprTests: public Test {};

//
// hasArg()
//

TEST_F(CallExprTests,
HasArgWorksCorrectly) {
	ExprVector args;
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	args.push_back(varX);
	ShPtr<Variable> varY(Variable::create("Y", IntType::create(32)));
	args.push_back(varY);
	ShPtr<CallExpr> call(CallExpr::create(Variable::create("foo", IntType::create(32)), args));

	EXPECT_FALSE(call->hasArg(0));
	EXPECT_TRUE(call->hasArg(1));
	EXPECT_TRUE(call->hasArg(2));
	EXPECT_FALSE(call->hasArg(3));
}

//
// getArg()
//

TEST_F(CallExprTests,
GetArg1ReturnsTheFirstArgument) {
	ExprVector args;
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	args.push_back(varX);
	ShPtr<CallExpr> call(CallExpr::create(Variable::create("foo", IntType::create(32)), args));

	EXPECT_EQ(varX, call->getArg(1)) <<
		"expected `" << varX->getName() << "`, "
		"got `" << call->getArg(1) << "`";
}

TEST_F(CallExprTests,
GetArg2ReturnsTheSecondArgument) {
	ExprVector args;
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	args.push_back(varX);
	ShPtr<Variable> varY(Variable::create("Y", IntType::create(32)));
	args.push_back(varY);
	ShPtr<CallExpr> call(CallExpr::create(Variable::create("foo", IntType::create(32)), args));

	EXPECT_EQ(varY, call->getArg(2)) <<
		"expected `" << varY->getName() << "`, "
		"got `" << call->getArg(2) << "`";
}

#if DEATH_TESTS_ENABLED
TEST_F(CallExprTests,
GetArgViolatedPreconditionTooLowArgument) {
	ExprVector args;
	ShPtr<CallExpr> call(CallExpr::create(Variable::create("foo", IntType::create(32)), args));

	EXPECT_DEATH(call->getArg(0), ".*getArg.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(CallExprTests,
GetArgViolatedPreconditionTooHighArgument) {
	ExprVector args;
	ShPtr<CallExpr> call(CallExpr::create(Variable::create("foo", IntType::create(32)), args));

	EXPECT_DEATH(call->getArg(1), ".*getArg.*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
