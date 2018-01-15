/**
* @file tests/llvmir2hll/hll/bracket_managers/c_bracket_manager_tests.cpp
* @brief Tests for the @c c_bracket_manager module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/hll/bracket_managers/c_bracket_manager.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/comma_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c c_bracket_manager module.
*/
class CBracketManagerTests: public TestsWithModule {};

TEST_F(CBracketManagerTests,
ManagerHasNonEmptyID) {
	CBracketManager cBrackets(module);

	EXPECT_TRUE(!cBrackets.getId().empty()) <<
		"the manager should have a non-empty ID";
}

TEST_F(CBracketManagerTests,
MulAdd) {
	// return 2 * (0 + a);
	//
	// expected output: return 2 * (0 + a);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			ConstInt::create(0, 64),
			varA
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			ConstInt::create(2, 64),
			addOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(CBracketManagerTests,
MulDivMul) {
	// return a * ((b / c) * 3);
	//
	// expected output: return a * b / c * 3;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			varB,
			varC
	));
	ShPtr<MulOpExpr> mulOpExpr1(
		MulOpExpr::create(
			divOpExpr,
			ConstInt::create(3, 64)
	));
	ShPtr<MulOpExpr> mulOpExpr2(
		MulOpExpr::create(
			varA,
			mulOpExpr1
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr2));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr1)) <<
		"not expected brackets around " << mulOpExpr1;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr2)) <<
		"not expected brackets around " << mulOpExpr2;
}

TEST_F(CBracketManagerTests,
MulDiv) {
	// return a * (b / c);
	//
	// expected output: return a * b / c;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			varB,
			varC
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			divOpExpr,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(CBracketManagerTests,
DivMul) {
	// return a / (b * c);
	//
	// expected output: return a / (b * c);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varB,
			varC
	));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			varA,
			mulOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(divOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(mulOpExpr)) <<
		"expected brackets around " << mulOpExpr;
}

TEST_F(CBracketManagerTests,
DivDivBracketsNeeded) {
	// return a / (b / c);
	//
	// expected output: return a / (b / c);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExprBC(
		DivOpExpr::create(
			varB,
			varC
	));
	ShPtr<DivOpExpr> divOpExprABC(
		DivOpExpr::create(
			varA,
			divOpExprBC
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(divOpExprABC));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExprABC)) <<
		"not expected brackets around " << divOpExprABC;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(divOpExprBC)) <<
		"expected brackets around " << divOpExprBC;
}

TEST_F(CBracketManagerTests,
DivDivBracketsNotNeeded) {
	// return ((a / b) / c);
	//
	// expected output: return a / b / c;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<DivOpExpr> divOpExprAB(
		DivOpExpr::create(
			varA,
			varB
	));
	ShPtr<DivOpExpr> divOpExprABC(
		DivOpExpr::create(
			divOpExprAB,
			varC
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(divOpExprABC));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExprAB)) <<
		"not expected brackets around " << divOpExprABC;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExprABC)) <<
		"not expected brackets around " << divOpExprABC;
}

TEST_F(CBracketManagerTests,
NotEqBracketsNotNeeded) {
	// return ((!a) == b);
	//
	// expected output: return !a == b;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<NotOpExpr> notOpExpr(
		NotOpExpr::create(
			varA
	));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			notOpExpr,
			varB
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(eqOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(notOpExpr)) <<
		"not expected brackets around " << notOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
}

TEST_F(CBracketManagerTests,
EqNotBracketsNeeded) {
	// return (a == (!b));
	//
	// expected output: return a == !b;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<NotOpExpr> notOpExpr(
		NotOpExpr::create(
			varB
	));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			notOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(eqOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(notOpExpr)) <<
		"not expected brackets around " << notOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
}

TEST_F(CBracketManagerTests,
NotEqGtEqGtLtEqLtNeqFirst) {
	// return (((((((!a) == b) >= c) > d) <= e) < f) != g);
	//
	// expected output: return (!a == b) >= c > d <= f < g != h;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	ShPtr<Variable> varE(Variable::create("e", IntType::create(16)));
	ShPtr<Variable> varF(Variable::create("f", IntType::create(16)));
	ShPtr<Variable> varG(Variable::create("g", IntType::create(16)));
	ShPtr<NotOpExpr> notOpExpr(
		NotOpExpr::create(
			varA
	));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			notOpExpr,
			varB
	));
	ShPtr<GtEqOpExpr> gtEqOpExpr(
		GtEqOpExpr::create(
			eqOpExpr,
			varC
	));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			gtEqOpExpr,
			varD
	));
	ShPtr<LtEqOpExpr> ltEqOpExpr(
		LtEqOpExpr::create(
			gtOpExpr,
			varE
	));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			ltEqOpExpr,
			varF
	));
	ShPtr<NeqOpExpr> neqOpExpr(
		NeqOpExpr::create(
			ltOpExpr,
			varG
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(neqOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(notOpExpr)) <<
		"not expected brackets around " << notOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(eqOpExpr)) <<
		"expected brackets around " << eqOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(gtEqOpExpr)) <<
		"not expected brackets around " << gtEqOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(gtOpExpr)) <<
		"not expected brackets around " << gtOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(ltEqOpExpr)) <<
		"not expected brackets around " << ltEqOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(neqOpExpr)) <<
		"not expected brackets around " << neqOpExpr;
}

TEST_F(CBracketManagerTests,
NotEqGtEqGtLtEqLtNeqSecond) {
	// return (!(a == (b >= (c > (d <= (e < (f != g))))));
	//
	// expected output: return !a == b >= (c > (d <= (e < (f != g)));
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	ShPtr<Variable> varE(Variable::create("e", IntType::create(16)));
	ShPtr<Variable> varF(Variable::create("f", IntType::create(16)));
	ShPtr<Variable> varG(Variable::create("g", IntType::create(16)));
	ShPtr<NeqOpExpr> neqOpExpr(
		NeqOpExpr::create(
			varF,
			varG
	));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varE,
			neqOpExpr
	));
	ShPtr<LtEqOpExpr> ltEqOpExpr(
		LtEqOpExpr::create(
			varD,
			ltOpExpr
	));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varC,
			ltEqOpExpr
	));
	ShPtr<GtEqOpExpr> gtEqOpExpr(
		GtEqOpExpr::create(
			varB,
			gtOpExpr
	));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			gtEqOpExpr
	));
	ShPtr<NotOpExpr> notOpExpr(
		NotOpExpr::create(
			eqOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(notOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(notOpExpr)) <<
		"expected brackets around " << notOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(eqOpExpr)) <<
		"expected brackets around " << eqOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(gtEqOpExpr)) <<
		"not expected brackets around " << gtEqOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(gtOpExpr)) <<
		"expected brackets around " << gtOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(ltEqOpExpr)) <<
		"expected brackets around " << ltEqOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(ltOpExpr)) <<
		"expected brackets around " << ltOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(neqOpExpr)) <<
		"expected brackets around " << neqOpExpr;
}

TEST_F(CBracketManagerTests,
DivAddSub) {
	// return a / (a + ((b + c) + (a - b)));
	//
	// expected output: return a / (a + b + c + a - b);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExprBC(
		AddOpExpr::create(
			varB,
			varC
	));
	ShPtr<SubOpExpr> subOpExprAB(
		SubOpExpr::create(
			varA,
			varB
	));
	ShPtr<AddOpExpr> addOpExprBCAB(
		AddOpExpr::create(
			addOpExprBC,
			subOpExprAB
	));
	ShPtr<AddOpExpr> addOpExprABCAB(
		AddOpExpr::create(
			varA,
			addOpExprBCAB
	));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			varA,
			addOpExprABCAB
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(divOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExprBC)) <<
		"not expected brackets around " << addOpExprBC;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(subOpExprAB)) <<
		"not expected brackets around " << subOpExprAB;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExprBCAB)) <<
		"not expected brackets around " << addOpExprBCAB;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(addOpExprABCAB)) <<
		"expected brackets around " << addOpExprABCAB;
}

TEST_F(CBracketManagerTests,
AddrDerefUnar) {
	// return (&(*(-a)));
	//
	// expected output: return &*-a;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<NegOpExpr> negOpExpr(
		NegOpExpr::create(
			varA
	));
	ShPtr<DerefOpExpr> derefOpExpr(
		DerefOpExpr::create(
			negOpExpr
	));
	ShPtr<AddressOpExpr> addressOpExpr(
		AddressOpExpr::create(
			derefOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(addressOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(negOpExpr)) <<
		"not expected brackets around " << negOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(derefOpExpr)) <<
		"not expected brackets around " << derefOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(addressOpExpr)) <<
		"not expected brackets around " << addressOpExpr;
}

TEST_F(CBracketManagerTests,
AddrBeforeArrayIndex) {
	// return (&(a))[0];
	//
	// expected output: return (&a)[0];
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddressOpExpr> addressOpExpr(
		AddressOpExpr::create(varA
	));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			addressOpExpr,
			ConstInt::create(0, 32)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(arrayIndexOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(addressOpExpr)) <<
		"expected brackets around " << addressOpExpr;
}

TEST_F(CBracketManagerTests,
AddrAfterArrayIndex) {
	// return &a[0];
	//
	// expected output: return &a[0];
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(0, 32)
	));
	ShPtr<AddressOpExpr> addressOpExpr(
		AddressOpExpr::create(arrayIndexOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(addressOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(arrayIndexOpExpr)) <<
		"not expected brackets around " << arrayIndexOpExpr;
}

TEST_F(CBracketManagerTests,
AddrDerefAndGtLtEq) {
	// return ((&(a <= b)) && (*(c > d)));
	//
	// expected output: return &(a <= b) && *(c > d);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<Variable> varD(Variable::create("a", IntType::create(16)));
	ShPtr<LtEqOpExpr> ltEqOpExpr(
		LtEqOpExpr::create(
			varA,
			varB
	));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varC,
			varD
	));
	ShPtr<AddressOpExpr> addressOpExpr(
		AddressOpExpr::create(
			ltEqOpExpr
	));
	ShPtr<DerefOpExpr> derefOpExpr(
		DerefOpExpr::create(
			gtOpExpr
	));
	ShPtr<AndOpExpr> andOpExpr(
		AndOpExpr::create(
			addressOpExpr,
			derefOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(andOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(andOpExpr)) <<
		"not expected brackets around " << andOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(derefOpExpr)) <<
		"not expected brackets around " << derefOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(addressOpExpr)) <<
		"not expected brackets around " << addressOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(ltEqOpExpr)) <<
		"expected brackets around " << ltEqOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(gtOpExpr)) <<
		"expected brackets around " << gtOpExpr;
}

TEST_F(CBracketManagerTests,
OneOperatorFromOnePrecedenceRowFirst) {
	// return ((((((((((*a) % b) + c) >> d) & e) ^ f) | g) == h) && i) || j);
	//
	// expected output: return (*a % b + c >> d & e ^ f | g) == h && i || j;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	ShPtr<Variable> varE(Variable::create("e", IntType::create(16)));
	ShPtr<Variable> varF(Variable::create("f", IntType::create(16)));
	ShPtr<Variable> varG(Variable::create("g", IntType::create(16)));
	ShPtr<Variable> varH(Variable::create("h", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<Variable> varJ(Variable::create("j", IntType::create(16)));
	ShPtr<DerefOpExpr> derefOpExpr(
		DerefOpExpr::create(
			varA
	));
	ShPtr<ModOpExpr> modOpExpr(
		ModOpExpr::create(
			derefOpExpr,
			varB
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			modOpExpr,
			varC
	));
	ShPtr<BitShrOpExpr> bitShrOpExpr(
		BitShrOpExpr::create(
			addOpExpr,
			varD
	));
	ShPtr<BitAndOpExpr> bitAndOpExpr(
		BitAndOpExpr::create(
			bitShrOpExpr,
			varE
	));
	ShPtr<BitXorOpExpr> bitXorOpExpr(
		BitXorOpExpr::create(
			bitAndOpExpr,
			varF
	));
	ShPtr<BitOrOpExpr> bitOrOpExpr(
		BitOrOpExpr::create(
			bitXorOpExpr,
			varG
	));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			bitOrOpExpr,
			varH
	));
	ShPtr<AndOpExpr> andOpExpr(
		AndOpExpr::create(
			eqOpExpr,
			varI
	));
	ShPtr<OrOpExpr> orOpExpr(
		OrOpExpr::create(
			andOpExpr,
			varJ
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(orOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(derefOpExpr)) <<
		"not expected brackets around " << derefOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(modOpExpr)) <<
		"not expected brackets around " << modOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(bitShrOpExpr)) <<
		"not expected brackets around " << bitShrOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(bitAndOpExpr)) <<
		"not expected brackets around " << bitAndOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(bitXorOpExpr)) <<
		"not expected brackets around " << bitXorOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(bitOrOpExpr)) <<
		"not expected brackets around " << bitOrOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(andOpExpr)) <<
		"not expected brackets around " << andOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(orOpExpr)) <<
		"not expected brackets around " << orOpExpr;
}

TEST_F(CBracketManagerTests,
OneOperatorFromOnePrecedenceRowSecond) {
	// return ((((((((((a || b) && c) != d) | e) ^ f) & g) << h) + i) / j)&);
	//
	// expected output: return ((((((((a || b) && c) != d | e) ^
	//					f) & g) << h) + i) / j)&;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	ShPtr<Variable> varE(Variable::create("e", IntType::create(16)));
	ShPtr<Variable> varF(Variable::create("f", IntType::create(16)));
	ShPtr<Variable> varG(Variable::create("g", IntType::create(16)));
	ShPtr<Variable> varH(Variable::create("h", IntType::create(16)));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(16)));
	ShPtr<Variable> varJ(Variable::create("j", IntType::create(16)));
	ShPtr<OrOpExpr> orOpExpr(
		OrOpExpr::create(
			varA,
			varB
	));
	ShPtr<AndOpExpr> andOpExpr(
		AndOpExpr::create(
			orOpExpr,
			varC
	));
	ShPtr<NeqOpExpr> neqOpExpr(
		NeqOpExpr::create(
			andOpExpr,
			varD
	));
	ShPtr<BitOrOpExpr> bitOrOpExpr(
		BitOrOpExpr::create(
			neqOpExpr,
			varE
	));
	ShPtr<BitXorOpExpr> bitXorOpExpr(
		BitXorOpExpr::create(
			bitOrOpExpr,
			varF
	));
	ShPtr<BitAndOpExpr> bitAndOpExpr(
		BitAndOpExpr::create(
			bitXorOpExpr,
			varG
	));
	ShPtr<BitShlOpExpr> bitShlOpExpr(
		BitShlOpExpr::create(
			bitAndOpExpr,
			varH
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			bitShlOpExpr,
			varI
	));
	ShPtr<DivOpExpr> divOpExpr(
		DivOpExpr::create(
			addOpExpr,
			varJ
	));
	ShPtr<AddressOpExpr> addressOpExpr(
		AddressOpExpr::create(
			divOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(addressOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(orOpExpr)) <<
		"expected brackets around " << orOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(andOpExpr)) <<
		"expected brackets around " << andOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(neqOpExpr)) <<
		"not expected brackets around " << neqOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(bitOrOpExpr)) <<
		"expected brackets around " << bitOrOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(bitXorOpExpr)) <<
		"expected brackets around " << bitXorOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(bitAndOpExpr)) <<
		"expected brackets around " << bitAndOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(bitShlOpExpr)) <<
		"expected brackets around " << bitShlOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(divOpExpr)) <<
		"expected brackets around " << divOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(addressOpExpr)) <<
		"not expected brackets around " << addressOpExpr;
}

TEST_F(CBracketManagerTests,
TernaryOpBracketsAreNotNeeded) {
	// return (a < b)? a : (b + c);
	//
	// expected output: return a < b? a : b + c;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varA,
			varB
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			varC
	));
	ShPtr<TernaryOpExpr> ternaryOpExpr(
		TernaryOpExpr::create(
			ltOpExpr,
			varA,
			addOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(ternaryOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(ternaryOpExpr)) <<
		"not expected brackets around " << ternaryOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
}

TEST_F(CBracketManagerTests,
TernaryOpBracketsAreNeededFalseCond) {
	// return 2 % ((a < b)? a : b + c);
	//
	// expected output: return 2 % (a < b? a : b + c);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varA,
			varB
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			varC
	));
	ShPtr<TernaryOpExpr> ternaryOpExpr(
		TernaryOpExpr::create(
			ltOpExpr,
			varA,
			addOpExpr
	));
	ShPtr<ModOpExpr> modOpExpr(
		ModOpExpr::create(
			ternaryOpExpr,
			ConstInt::create(2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(modOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(modOpExpr)) <<
		"not expected brackets around " << modOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(ternaryOpExpr)) <<
		"expected brackets around " << ternaryOpExpr;
}

TEST_F(CBracketManagerTests,
TernaryOpBracketsAreNeededTrueCond) {
	// return ((a < b)? a : b + c) % 5;
	//
	// expected output: return (a < b? a : b + c) % 5;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	ShPtr<LtOpExpr> ltOpExpr(
		LtOpExpr::create(
			varA,
			varB
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varB,
			varC
	));
	ShPtr<TernaryOpExpr> ternaryOpExpr(
		TernaryOpExpr::create(
			ltOpExpr,
			varA,
			addOpExpr
	));
	ShPtr<ModOpExpr> modOpExpr(
		ModOpExpr::create(
			ConstInt::create(5, 64),
			ternaryOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(modOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(modOpExpr)) <<
		"not expected brackets around " << modOpExpr;
	EXPECT_TRUE(cBrackets.areBracketsNeeded(ternaryOpExpr)) <<
		"expected brackets around " << ternaryOpExpr;
}

TEST_F(CBracketManagerTests,
CastBracketsNotNeeded) {
	// return IntToPtrCastExpr(a) + 2;
	//
	// expected output: return IntToPtrCastExpr(a) + 2;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<IntToPtrCastExpr> intToPtrCastExpr(
		IntToPtrCastExpr::create(
			varA,
			IntType::create(16)
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			intToPtrCastExpr,
			ConstInt::create(2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(addOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
}

TEST_F(CBracketManagerTests,
CastBracketsNeeded) {
	// return IntToPtrCastExpr(a + 2);
	//
	// expected output: return IntToPtrCastExpr(a + 2);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<IntToPtrCastExpr> intToPtrCastExpr(
		IntToPtrCastExpr::create(
			addOpExpr,
			IntType::create(16)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(intToPtrCastExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
}

TEST_F(CBracketManagerTests,
CastBeforeArrayIndexBracketsNeeded) {
	// return IntToPtrCastExpr(a)[1];
	//
	// expected output: (IntToPtrCastExpr(a))[1]
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<IntToPtrCastExpr> intToPtrCastExpr(
		IntToPtrCastExpr::create(
			varA,
			IntType::create(16)
	));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			intToPtrCastExpr,
			ConstInt::create(1, 32)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(arrayIndexOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(intToPtrCastExpr)) <<
		"expected brackets around " << intToPtrCastExpr;
}

TEST_F(CBracketManagerTests,
CastBeforeStructIndexBracketsNeeded) {
	// return IntToPtrCastExpr(a).e1;
	//
	// expected output: (IntToPtrCastExpr(a)).e1
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<IntToPtrCastExpr> intToPtrCastExpr(
		IntToPtrCastExpr::create(
			varA,
			IntType::create(16)
	));
	ShPtr<StructIndexOpExpr> structIndexOpExpr(
		StructIndexOpExpr::create(
			intToPtrCastExpr,
			ConstInt::create(1, 32)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(structIndexOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(intToPtrCastExpr)) <<
		"expected brackets around " << intToPtrCastExpr;
}

TEST_F(CBracketManagerTests,
CallExprWithArgumentsBracketsNotNeeded) {
	// return varA(a + 2);
	//
	// For this purpose is calledExpr substitute with Variable. This is only
	// for make simplifier function and have no effect on result.
	//
	// expected output: return varA(a + 2);
	//
	ExprVector args;
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	args.push_back(addOpExpr);
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			varA,
			args
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(callExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
}

TEST_F(CBracketManagerTests,
CallExprInExpressionWithArgumentsBracketsNotNeeded) {
	// return a * varA(a - 2);
	//
	// For this purpose is calledExpr substitute with Variable. This is only
	// for make simplifier function and have no effect on result.
	//
	// expected output: return a * varA(a - 2);
	//
	ExprVector args;
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	args.push_back(subOpExpr);
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			varA,
			args
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varA,
			callExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(subOpExpr)) <<
		"not expected brackets around " << subOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(callExpr)) <<
		"not expected brackets around " << callExpr;
}

TEST_F(CBracketManagerTests,
CallExprOfArrayIndexBracketsNotNeeded) {
	// return ((a)[1])();
	//
	// expected output: a[1]();
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			arrayIndexOpExpr,
			ExprVector()
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(callExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(arrayIndexOpExpr)) <<
		"not expected brackets around " << arrayIndexOpExpr;
}

TEST_F(CBracketManagerTests,
CalledExprIsCastBracketsAreNeeded) {
	// return ((type)a)();
	//
	// expected output: ((type)a)();
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<BitCastExpr> castExpr(
		BitCastExpr::create(
			varA,
			IntType::create(32)
	));
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			castExpr,
			ExprVector()
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(callExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(castExpr)) <<
		"expected brackets around " << castExpr;
}

TEST_F(CBracketManagerTests,
CalledExprIsDerefBracketsAreNeeded) {
	// return (*a)();
	//
	// expected output: (*a)();
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<DerefOpExpr> derefOpExpr(
		DerefOpExpr::create(varA)
	);
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			derefOpExpr,
			ExprVector()
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(callExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(derefOpExpr)) <<
		"expected brackets around " << derefOpExpr;
}

TEST_F(CBracketManagerTests,
ArrayIndexOpExprBracketsNotNeeded) {
	// return a[a + 2];
	//
	// expected output: return a[a + 2];
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			addOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(arrayIndexOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
}

TEST_F(CBracketManagerTests,
ArrayIndexOpExprBracketsNotNeededIfJustVariableIsIndexed) {
	// return (a)[2];
	//
	// expected output: return a[2];
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(arrayIndexOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
}

TEST_F(CBracketManagerTests,
ArrayIndexOpExprInExpressionBracketsNotNeeded) {
	// return a * a[a - 2];
	//
	// expected output: return a * a[a - 2];
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			subOpExpr
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varA,
			arrayIndexOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(subOpExpr)) <<
		"not expected brackets around " << subOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(arrayIndexOpExpr)) <<
		"not expected brackets around " << arrayIndexOpExpr;
}

TEST_F(CBracketManagerTests,
StructIndexOpExprInExpressionBracketsNotNeeded) {
	// return ((a * varA.e2) + 2);
	//
	// expected output: return a * varA.e2 + 2;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<StructIndexOpExpr> structIndexOpExpr(
		StructIndexOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varA,
			structIndexOpExpr
	));

	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			mulOpExpr,
			ConstInt::create(2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(addOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(CBracketManagerTests,
StructIndexOpExprBracketsNotNeededIfJustVariableIsIndexed) {
	// return (a).e1;
	//
	// expected output: return a.e1;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<StructIndexOpExpr> structIndexOpExpr(
		StructIndexOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(structIndexOpExpr));
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
}

TEST_F(CBracketManagerTests,
MulAssign) {
	// return 2 * (a = 0);
	//
	// expected output: return 2 * (a = 0);
	//
	auto varA = Variable::create("a", IntType::create(16));
	auto assignOpExpr = AssignOpExpr::create(
		varA,
		ConstInt::create(0, 64)
	);
	auto mulOpExpr = MulOpExpr::create(
		ConstInt::create(2, 64),
		assignOpExpr
	);
	auto returnStmt = ReturnStmt::create(mulOpExpr);
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(assignOpExpr)) <<
		"expected brackets around " << assignOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(CBracketManagerTests,
AssignAssignBracketsNotNeeded) {
	// return a = (b = c);
	//
	// expected output: return a = b = c;
	//
	auto varA = Variable::create("a", IntType::create(16));
	auto varB = Variable::create("b", IntType::create(16));
	auto varC = Variable::create("c", IntType::create(16));
	auto assignBC = AssignOpExpr::create(varB, varC);
	auto assignABC = AssignOpExpr::create(varA, assignBC);
	auto returnStmt = ReturnStmt::create(assignABC);
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(assignABC)) <<
		"not expected brackets around " << assignABC;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(assignBC)) <<
		"not expected brackets around " << assignBC;
}

TEST_F(CBracketManagerTests,
MulComma) {
	// return 2 * (a, 0);
	//
	// expected output: return 2 * (a, 0);
	//
	auto varA = Variable::create("a", IntType::create(16));
	auto commaOpExpr = CommaOpExpr::create(
		varA,
		ConstInt::create(0, 64)
	);
	auto mulOpExpr = MulOpExpr::create(
		ConstInt::create(2, 64),
		commaOpExpr
	);
	auto returnStmt = ReturnStmt::create(mulOpExpr);
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_TRUE(cBrackets.areBracketsNeeded(commaOpExpr)) <<
		"expected brackets around " << commaOpExpr;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(CBracketManagerTests,
CommaCommaBracketsNotNeeded) {
	// return (a, b), c;
	//
	// expected output: return a, b, c;
	//
	auto varA = Variable::create("a", IntType::create(16));
	auto varB = Variable::create("b", IntType::create(16));
	auto varC = Variable::create("c", IntType::create(16));
	auto commaAB = CommaOpExpr::create(varA, varB);
	auto commaABC = CommaOpExpr::create(commaAB, varC);
	auto returnStmt = ReturnStmt::create(commaABC);
	testFunc->setBody(returnStmt);
	CBracketManager cBrackets(module);

	EXPECT_FALSE(cBrackets.areBracketsNeeded(commaABC)) <<
		"not expected brackets around " << commaABC;
	EXPECT_FALSE(cBrackets.areBracketsNeeded(commaAB)) <<
		"not expected brackets around " << commaAB;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
