/**
* @file tests/llvmir2hll/hll/compound_op_managers/no_compound_op_manager_tests.cpp
* @brief Tests for the @c no_compound_op_manager module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/compound_op_managers/no_compound_op_manager.h"
#include "llvmir2hll/hll/compound_op_managers/compound_op_manager_tests.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c no_compound_op_manager module.
*/
class NoCompoundOpManagerTests: public CompoundOpManagerTests {
protected:
	virtual void SetUp() override {
		CompoundOpManagerTests::SetUp();
		compoundOpManager = std::make_shared<NoCompoundOpManager>();
	}
};

TEST_F(NoCompoundOpManagerTests,
ManagerHasNonEmptyID) {
	EXPECT_TRUE(!compoundOpManager->getId().empty()) <<
		"the manager should have a non-empty ID";
}

//
// Not optimized to compound operator.
//

TEST_F(NoCompoundOpManagerTests,
AddToCompoundOpVarOnLeftCantBeOptimized) {
	// a = a + 2;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			addOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", addOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
SubToCompoundOpVarOnLeftCantBeOptimized) {
	// a = a - 2;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			subOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", subOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
MulToCompoundOpVarOnRightCantBeOptimized) {
	// a = b * a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varB,
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			mulOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", mulOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
DivToCompoundOpArrayIndexOnLeftCantBeOptimized) {
	// a[2] = a[2] / a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			arrayIndexOpExpr,
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			arrayIndexOpExpr,
			divOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", divOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
ModToCompoundOpStructIndexOnLeftCantBeOptimized) {
	// a.e2 = a.e2 % b;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<StructIndexOpExpr> structIndexOpExpr(
		StructIndexOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<ModOpExpr> modOpExpr(
		ModOpExpr::create(
			structIndexOpExpr,
			varB
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			structIndexOpExpr,
			modOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", modOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitShlOpExprToCompoundOpVarOnLeftCantBeOptimized) {
	// a = a << 3;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitShlOpExpr> bitShlOpExpr(
		BitShlOpExpr::create(
			varA,
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitShlOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitShlOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitShrOpExprToCompoundOpVarOnLeftCantBeOptimized) {
	// a = a >> 3;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitShrOpExpr> bitShrOpExpr(
		BitShrOpExpr::create(
			varA,
			ConstInt::create(3, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitShrOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitShrOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitAndToCompoundOpVarOnRightCantBeOptimized) {
	// a = b & a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<BitAndOpExpr> bitAndOpExpr(
		BitAndOpExpr::create(
			varB,
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitAndOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitAndOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitOrToCompoundOpVarOnRightCantBeOptimized) {
	// a = 2 | a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitOrOpExpr> bitOrOpExpr(
		BitOrOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitOrOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitOrOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitXorToCompoundOpVarOnRightCantBeOptimized) {
	// a = 2 ^ a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitXorOpExpr> bitXorOpExpr(
		BitXorOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitXorOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitXorOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
SubToCompoundOpVarOnLeftMoreComplicatedRhsOfAssignStmtCantBeOptimized) {
	// a = a - (2 + (a * 4));
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			mulOpExpr
	));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			varA,
			addOpExpr
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			subOpExpr
	));

	CompoundOpManager::CompoundOp expectedResult("=", subOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
EqOpExprNotSupportedCompoundOperatorCantBeOptimized) {
	// a = a == 2;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			eqOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", eqOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
SubOpExprVarOnRightCantBeOptimizedCantBeOptimized) {
	// a = 2 - a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			subOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", subOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
DivOpExprVarOnRightCantBeOptimizedCantBeOptimized) {
	// a = 2 / a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			divOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", divOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
ModOpExprVarOnRightCantBeOptimizedCantBeOptimized) {
	// a = 2 % a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ModOpExpr> modOpExpr(
		ModOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			modOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", modOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitShlOpExprVarOnRightCantBeOptimizedCantBeOptimized) {
	// a = 2 << a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitShlOpExpr> bitShlOpExpr(
		BitShlOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitShlOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitShlOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
BitShrOpExprVarOnRightCantBeOptimizedCantBeOptimized) {
	// a = 2 >> a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitShrOpExpr> bitShrOpExpr(
		BitShrOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			bitShrOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", bitShrOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
SubOpExprRightOperandAddOpExprWithVarEqWithLhsOfAssignCantBeOptimized) {
	// a = 2 - (a + 4);
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			addOpExpr
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			subOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", subOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
AddOpExprNotVarOrArrayIndexOrStructIndexOnLhsOfAssignStmtCantBeOptimized) {
	// 2 = 2 + a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ConstInt> constInt(ConstInt::create(2, 64));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			constInt,
			varA
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			constInt,
			addOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", addOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

TEST_F(NoCompoundOpManagerTests,
AddOpExprNotEqLhsOfAssignStmtWithOneOperandOfAddOpExprCantBeOptimized) {
	// a = b + b;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			varB
	));
	ShPtr<AssignStmt> assignStmt(
		AssignStmt::create(
			varA,
			addOpExpr
	));
	CompoundOpManager::CompoundOp expectedResult("=", addOpExpr);
	tryToOptimizeAndCheckResult(assignStmt, expectedResult);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
