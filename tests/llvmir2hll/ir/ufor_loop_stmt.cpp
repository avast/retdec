/**
* @file tests/llvmir2hll/ir/ufor_loop_stmt.cpp
* @brief Tests for the @c ufor_loop_stmt module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c ufor_loop_stmt module.
*/
class UForLoopStmtTests: public Test {
protected:
	ShPtr<UForLoopStmt> createLoop();
};

/**
* @brief A helper function to make tests more readable.
*/
ShPtr<UForLoopStmt> UForLoopStmtTests::createLoop() {
	return UForLoopStmt::create(
		ConstInt::create(1, 32),
		ConstInt::create(2, 32),
		ConstInt::create(3, 32),
		EmptyStmt::create()
	);
}

TEST_F(UForLoopStmtTests,
AttributesCanBeObtainedAfterCreation) {
	auto init = ConstInt::create(1, 32);
	auto cond = ConstInt::create(2, 32);
	auto step = ConstInt::create(3, 32);
	auto body = EmptyStmt::create();
	auto succ = EmptyStmt::create();

	auto loop = UForLoopStmt::create(init, cond, step, body, succ);

	ASSERT_EQ(init, loop->getInit());
	ASSERT_EQ(cond, loop->getCond());
	ASSERT_EQ(step, loop->getStep());
	ASSERT_EQ(body, loop->getBody());
	ASSERT_EQ(succ, loop->getSuccessor());
}

TEST_F(UForLoopStmtTests,
AttributesHaveCorrectValuesAfterSet) {
	auto init1 = ConstInt::create(1, 32);
	auto cond1 = ConstInt::create(2, 32);
	auto step1 = ConstInt::create(3, 32);
	auto body1 = EmptyStmt::create();
	auto succ1 = EmptyStmt::create();
	auto loop = UForLoopStmt::create(init1, cond1, step1, body1, succ1);
	auto init2 = ConstInt::create(1, 32);
	auto cond2 = ConstInt::create(2, 32);
	auto step2 = ConstInt::create(3, 32);
	auto body2 = EmptyStmt::create();
	auto succ2 = EmptyStmt::create();

	loop->setInit(init2);
	loop->setCond(cond2);
	loop->setStep(step2);
	loop->setBody(body2);
	loop->setSuccessor(succ2);

	ASSERT_EQ(init2, loop->getInit());
	ASSERT_EQ(cond2, loop->getCond());
	ASSERT_EQ(step2, loop->getStep());
	ASSERT_EQ(body2, loop->getBody());
	ASSERT_EQ(succ2, loop->getSuccessor());
}

//
// isInitDefinition(), markInitAsDefinition()
//

TEST_F(UForLoopStmtTests,
IsInitDefinitionReturnsFalseByDefault) {
	auto loop = createLoop();

	ASSERT_FALSE(loop->isInitDefinition());
}

TEST_F(UForLoopStmtTests,
IsInitDefinitionReturnsTrueWhenMarkedAsDefinition) {
	auto loop = createLoop();
	loop->markInitAsDefinition();

	ASSERT_TRUE(loop->isInitDefinition());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
