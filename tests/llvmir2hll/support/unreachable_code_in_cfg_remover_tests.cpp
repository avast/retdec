/**
* @file tests/llvmir2hll/support/unreachable_code_in_cfg_remover_tests.cpp
* @brief Tests for the @c unreachable_code_in_cfg_remover module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/unreachable_code_in_cfg_remover.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c unreachable_code_in_cfg_remover module.
*/
class UnreachableCodeInCFGRemoverTests: public TestsWithModule {};

TEST_F(UnreachableCodeInCFGRemoverTests,
DoNotRemoveAnythingInEmptyFunction) {
	// Set-up the module.
	//
	// void test() {}
	//
	// -

	// Perform the removal.
	UnreachableCodeInCFGRemover::removeCode(module);

	// Check that the output is correct.
	EXPECT_TRUE(isa<EmptyStmt>(testFunc->getBody()));
}

TEST_F(UnreachableCodeInCFGRemoverTests,
IfThereIsUnreachableCodeAfterIfStatementRemoveIt) {
	// Set-up the module.
	//
	// void test() {
	//     if (1) {
	//         return 1;
	//     } else {
	//         return 2;
	//     }
	//     return 0;       <-- to be removed
	// }
	//
	ShPtr<ReturnStmt> return0(ReturnStmt::create(ConstInt::create(0, 32)));
	ShPtr<ReturnStmt> return1(ReturnStmt::create(ConstInt::create(1, 32)));
	ShPtr<ReturnStmt> return2(ReturnStmt::create(ConstInt::create(2, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32),
		return1, return0));
	ifStmt->setElseClause(return2);
	testFunc->setBody(ifStmt);

	// Perform the removal.
	UnreachableCodeInCFGRemover::removeCode(module);

	// Check that the output is correct.
	EXPECT_TRUE(!ifStmt->hasSuccessor());
	EXPECT_EQ(return1, ifStmt->getFirstIfBody());
	EXPECT_EQ(return2, ifStmt->getElseClause());
}

TEST_F(UnreachableCodeInCFGRemoverTests,
EmptyStatementIsRemovedIfItHadSuccessorThatWasRemoved) {
	// Set-up the module.
	//
	// void test() {
	//     if (1) {
	//         return 1;
	//     } else {
	//         return 2;
	//     }
	//     /* empty statement */  <-- to be removed
	//     return 0;              <-- to be removed
	// }
	//
	ShPtr<ReturnStmt> return0(ReturnStmt::create(ConstInt::create(0, 32)));
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create(return0));
	ShPtr<ReturnStmt> return1(ReturnStmt::create(ConstInt::create(1, 32)));
	ShPtr<ReturnStmt> return2(ReturnStmt::create(ConstInt::create(2, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32),
		return1, emptyStmt));
	ifStmt->setElseClause(return2);
	testFunc->setBody(ifStmt);

	// Perform the removal.
	UnreachableCodeInCFGRemover::removeCode(module);

	// Check that the output is correct.
	EXPECT_TRUE(!ifStmt->hasSuccessor());
	EXPECT_EQ(return1, ifStmt->getFirstIfBody());
	EXPECT_EQ(return2, ifStmt->getElseClause());
}

TEST_F(UnreachableCodeInCFGRemoverTests,
EmptyStatementWhoseSuccessorIsNotRemovedIsKept) {
	// Set-up the module.
	//
	// void test() {
	//     if (1) {
	//         /* empty statement */  <-- to be kept
	//         return 1;
	//     } else {
	//         return 2;
	//     }
	//     return 0;                  <-- to be removed
	// }
	//
	ShPtr<ReturnStmt> return0(ReturnStmt::create(ConstInt::create(0, 32)));
	ShPtr<ReturnStmt> return1(ReturnStmt::create(ConstInt::create(1, 32)));
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create(return1));
	ShPtr<ReturnStmt> return2(ReturnStmt::create(ConstInt::create(2, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32),
		emptyStmt, return0));
	ifStmt->setElseClause(return2);
	testFunc->setBody(ifStmt);

	// Perform the removal.
	UnreachableCodeInCFGRemover::removeCode(module);

	// Check that the output is correct.
	EXPECT_TRUE(!ifStmt->hasSuccessor());
	EXPECT_EQ(emptyStmt, ifStmt->getFirstIfBody());
	EXPECT_EQ(return2, ifStmt->getElseClause());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
