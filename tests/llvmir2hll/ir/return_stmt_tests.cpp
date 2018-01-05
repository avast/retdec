/*
* @file tests/llvmir2hll/ir/return_stmt_tests.cpp
* @brief Tests for the @c return_stmt module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c return_stmt module.
*/
class ReturnStmtTests: public Test {};

//
// hasRetVal()
//

TEST_F(ReturnStmtTests,
HasRetValReturnsFalseIfReturnStatementDoesNotHaveReturnValue) {
	auto returnStmt = ReturnStmt::create();

	ASSERT_FALSE(returnStmt->hasRetVal());
}

TEST_F(ReturnStmtTests,
HasRetValReturnsTrueIfReturnStatementHasReturnValue) {
	auto returnValue = ConstInt::create(1, 32);
	auto returnStmt = ReturnStmt::create(returnValue);

	ASSERT_TRUE(returnStmt->hasRetVal());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
