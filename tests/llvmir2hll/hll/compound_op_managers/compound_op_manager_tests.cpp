/**
* @file tests/llvmir2hll/hll/compound_op_managers/compound_op_manager_tests.cpp
* @brief Implementation of CompoundOpManagerTests.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/compound_op_manager.h"
#include "llvmir2hll/hll/compound_op_managers/compound_op_manager_tests.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/expression.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tries to optimize @a stmt and compare with expected result in @a
*        expectedResult
*
* @param[in] stmt Statement to optimize.
* @param[in] expectedResult Expected result.
*/
void CompoundOpManagerTests::tryToOptimizeAndCheckResult(ShPtr<AssignStmt> stmt,
		CompoundOpManager::CompoundOp expectedResult) {
	CompoundOpManager::CompoundOp compoundResult(
		compoundOpManager->tryOptimizeToCompoundOp(stmt));
	EXPECT_EQ(expectedResult.getOperator(), compoundResult.getOperator()) <<
		"expected `" << expectedResult.getOperator() << "`, "
		"got `" << compoundResult.getOperator() << "`";
	ASSERT_EQ(expectedResult.isUnaryOperator(),
			compoundResult.isUnaryOperator()) <<
		"expected a " << (expectedResult.isUnaryOperator() ?
			"unary" : "binary") << " operator, " <<
		"got a " << (compoundResult.isUnaryOperator() ?
			"unary" : "binary") << " operator";
	// The operand is only relevant for binary operators.
	if (compoundResult.isBinaryOperator()) {
		ASSERT_TRUE(compoundResult.getOperand()->isEqualTo(expectedResult.getOperand())) <<
			"expected `" << expectedResult.getOperand() << "`, " <<
			"got `" << compoundResult.getOperand() << "`";
	}
}

TEST_F(CompoundOpManagerTests,
CompoundOpUnaryOperatorIsUnary) {
	CompoundOpManager::CompoundOp unaryOp("++");
	EXPECT_TRUE(unaryOp.isUnaryOperator());
	EXPECT_FALSE(unaryOp.isBinaryOperator());
}

TEST_F(CompoundOpManagerTests,
CompoundOpBinaryOperatorIsBinary) {
	CompoundOpManager::CompoundOp binaryOp("+=", ConstInt::create(1, 32));
	EXPECT_TRUE(binaryOp.isBinaryOperator());
	EXPECT_FALSE(binaryOp.isUnaryOperator());
}

TEST_F(CompoundOpManagerTests,
CompoundOpGetOperatorReturnsTheOperator) {
	CompoundOpManager::CompoundOp unaryOp("++");
	EXPECT_EQ("++", unaryOp.getOperator());

	CompoundOpManager::CompoundOp binaryOp("+=", ConstInt::create(1, 32));
	EXPECT_EQ("+=", binaryOp.getOperator());
}

TEST_F(CompoundOpManagerTests,
CompoundOpGetOperandReturnsTheOperandForBinaryOperator) {
	ShPtr<Expression> operand(ConstInt::create(1, 32));
	CompoundOpManager::CompoundOp binaryOp("+=", operand);
	EXPECT_EQ(operand, binaryOp.getOperand());
}

#if DEATH_TESTS_ENABLED
TEST_F(CompoundOpManagerTests,
CompoundOpGetOperandForUnaryOperatorPreconditionFail) {
	CompoundOpManager::CompoundOp unaryOp("++");
	EXPECT_DEATH(unaryOp.getOperand(), ".*getOperand.*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
