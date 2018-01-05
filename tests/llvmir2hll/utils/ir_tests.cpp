/**
* @file tests/llvmir2hll/utils/ir_tests.cpp
* @brief Tests for the @c ir module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/utils/ir.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c ir module.
*/
class IRTests: public Test {};

//
// skipDerefs()
//

TEST_F(IRTests,
SkipDerefsInExpressionWithNoDereferencesReturnsTheOriginalExpression) {
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	EXPECT_EQ(varX, skipDerefs(varX));
}

TEST_F(IRTests,
SkipDerefsInExpressionWithDereferencesSkipsThem) {
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	ShPtr<DerefOpExpr> derefVarX(DerefOpExpr::create(varX));
	ShPtr<DerefOpExpr> derefDerefVarX(DerefOpExpr::create(derefVarX));
	EXPECT_EQ(varX, skipDerefs(derefVarX));
}

TEST_F(IRTests,
SkipDerefsDereferencesInsideExpressionAreNotSkipped) {
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	ShPtr<DerefOpExpr> derefVarX(DerefOpExpr::create(varX));
	ShPtr<AddressOpExpr> addressDerefVarX(AddressOpExpr::create(derefVarX));
	EXPECT_EQ(addressDerefVarX, skipDerefs(addressDerefVarX));
}

//
// skipAddresses()
//

TEST_F(IRTests,
SkipAddressesInExpressionWithNoAddressesReturnsTheOriginalExpression) {
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	EXPECT_EQ(varX, skipAddresses(varX));
}

TEST_F(IRTests,
SkipAddressesInExpressionWithAddressesSkipsThem) {
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	ShPtr<AddressOpExpr> derefVarX(AddressOpExpr::create(varX));
	ShPtr<AddressOpExpr> derefDerefVarX(AddressOpExpr::create(derefVarX));
	EXPECT_EQ(varX, skipAddresses(derefVarX));
}

TEST_F(IRTests,
SkipAddressesDereferencesInsideExpressionAreNotSkipped) {
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	ShPtr<AddressOpExpr> addressVarX(AddressOpExpr::create(varX));
	ShPtr<DerefOpExpr> derefAddressVarX(DerefOpExpr::create(addressVarX));
	EXPECT_EQ(derefAddressVarX, skipAddresses(derefAddressVarX));
}

//
// isWhileTrueLoop()
//

TEST_F(IRTests,
IsWhileTrueLoopReturnsTrueForWhileTrueLoop) {
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(
		ConstBool::create(true), emptyStmt));
	EXPECT_TRUE(isWhileTrueLoop(whileLoopStmt));
}

TEST_F(IRTests,
IsWhileTrueLoopReturnsFalseForNonWhileTrueLoop) {
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(
		ConstBool::create(false), emptyStmt));
	EXPECT_FALSE(isWhileTrueLoop(whileLoopStmt));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
