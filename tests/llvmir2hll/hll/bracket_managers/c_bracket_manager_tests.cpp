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
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			ConstInt::create(0, 64),
			varA
	));
	MulOpExpr* mulOpExpr(
		MulOpExpr::create(
			ConstInt::create(2, 64),
			addOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(mulOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	DivOpExpr* divOpExpr(
		DivOpExpr::create(
			varB,
			varC
	));
	MulOpExpr* mulOpExpr1(
		MulOpExpr::create(
			divOpExpr,
			ConstInt::create(3, 64)
	));
	MulOpExpr* mulOpExpr2(
		MulOpExpr::create(
			varA,
			mulOpExpr1
	));
	ReturnStmt* returnStmt(ReturnStmt::create(mulOpExpr2));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	DivOpExpr* divOpExpr(
		DivOpExpr::create(
			varB,
			varC
	));
	MulOpExpr* mulOpExpr(
		MulOpExpr::create(
			divOpExpr,
			varA
	));
	ReturnStmt* returnStmt(ReturnStmt::create(mulOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	MulOpExpr* mulOpExpr(
		MulOpExpr::create(
			varB,
			varC
	));
	DivOpExpr* divOpExpr(
		DivOpExpr::create(
			varA,
			mulOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(divOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	DivOpExpr* divOpExprBC(
		DivOpExpr::create(
			varB,
			varC
	));
	DivOpExpr* divOpExprABC(
		DivOpExpr::create(
			varA,
			divOpExprBC
	));
	ReturnStmt* returnStmt(ReturnStmt::create(divOpExprABC));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	DivOpExpr* divOpExprAB(
		DivOpExpr::create(
			varA,
			varB
	));
	DivOpExpr* divOpExprABC(
		DivOpExpr::create(
			divOpExprAB,
			varC
	));
	ReturnStmt* returnStmt(ReturnStmt::create(divOpExprABC));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	NotOpExpr* notOpExpr(
		NotOpExpr::create(
			varA
	));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			notOpExpr,
			varB
	));
	ReturnStmt* returnStmt(ReturnStmt::create(eqOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	NotOpExpr* notOpExpr(
		NotOpExpr::create(
			varB
	));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			varA,
			notOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(eqOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	Variable* varD(Variable::create("d", IntType::create(16)));
	Variable* varE(Variable::create("e", IntType::create(16)));
	Variable* varF(Variable::create("f", IntType::create(16)));
	Variable* varG(Variable::create("g", IntType::create(16)));
	NotOpExpr* notOpExpr(
		NotOpExpr::create(
			varA
	));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			notOpExpr,
			varB
	));
	GtEqOpExpr* gtEqOpExpr(
		GtEqOpExpr::create(
			eqOpExpr,
			varC
	));
	GtOpExpr* gtOpExpr(
		GtOpExpr::create(
			gtEqOpExpr,
			varD
	));
	LtEqOpExpr* ltEqOpExpr(
		LtEqOpExpr::create(
			gtOpExpr,
			varE
	));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			ltEqOpExpr,
			varF
	));
	NeqOpExpr* neqOpExpr(
		NeqOpExpr::create(
			ltOpExpr,
			varG
	));
	ReturnStmt* returnStmt(ReturnStmt::create(neqOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	Variable* varD(Variable::create("d", IntType::create(16)));
	Variable* varE(Variable::create("e", IntType::create(16)));
	Variable* varF(Variable::create("f", IntType::create(16)));
	Variable* varG(Variable::create("g", IntType::create(16)));
	NeqOpExpr* neqOpExpr(
		NeqOpExpr::create(
			varF,
			varG
	));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varE,
			neqOpExpr
	));
	LtEqOpExpr* ltEqOpExpr(
		LtEqOpExpr::create(
			varD,
			ltOpExpr
	));
	GtOpExpr* gtOpExpr(
		GtOpExpr::create(
			varC,
			ltEqOpExpr
	));
	GtEqOpExpr* gtEqOpExpr(
		GtEqOpExpr::create(
			varB,
			gtOpExpr
	));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			varA,
			gtEqOpExpr
	));
	NotOpExpr* notOpExpr(
		NotOpExpr::create(
			eqOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(notOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	AddOpExpr* addOpExprBC(
		AddOpExpr::create(
			varB,
			varC
	));
	SubOpExpr* subOpExprAB(
		SubOpExpr::create(
			varA,
			varB
	));
	AddOpExpr* addOpExprBCAB(
		AddOpExpr::create(
			addOpExprBC,
			subOpExprAB
	));
	AddOpExpr* addOpExprABCAB(
		AddOpExpr::create(
			varA,
			addOpExprBCAB
	));
	DivOpExpr* divOpExpr(
		DivOpExpr::create(
			varA,
			addOpExprABCAB
	));
	ReturnStmt* returnStmt(ReturnStmt::create(divOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	NegOpExpr* negOpExpr(
		NegOpExpr::create(
			varA
	));
	DerefOpExpr* derefOpExpr(
		DerefOpExpr::create(
			negOpExpr
	));
	AddressOpExpr* addressOpExpr(
		AddressOpExpr::create(
			derefOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(addressOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddressOpExpr* addressOpExpr(
		AddressOpExpr::create(varA
	));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			addressOpExpr,
			ConstInt::create(0, 32)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(arrayIndexOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(0, 32)
	));
	AddressOpExpr* addressOpExpr(
		AddressOpExpr::create(arrayIndexOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(addressOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	Variable* varD(Variable::create("a", IntType::create(16)));
	LtEqOpExpr* ltEqOpExpr(
		LtEqOpExpr::create(
			varA,
			varB
	));
	GtOpExpr* gtOpExpr(
		GtOpExpr::create(
			varC,
			varD
	));
	AddressOpExpr* addressOpExpr(
		AddressOpExpr::create(
			ltEqOpExpr
	));
	DerefOpExpr* derefOpExpr(
		DerefOpExpr::create(
			gtOpExpr
	));
	AndOpExpr* andOpExpr(
		AndOpExpr::create(
			addressOpExpr,
			derefOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(andOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	Variable* varD(Variable::create("d", IntType::create(16)));
	Variable* varE(Variable::create("e", IntType::create(16)));
	Variable* varF(Variable::create("f", IntType::create(16)));
	Variable* varG(Variable::create("g", IntType::create(16)));
	Variable* varH(Variable::create("h", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	Variable* varJ(Variable::create("j", IntType::create(16)));
	DerefOpExpr* derefOpExpr(
		DerefOpExpr::create(
			varA
	));
	ModOpExpr* modOpExpr(
		ModOpExpr::create(
			derefOpExpr,
			varB
	));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			modOpExpr,
			varC
	));
	BitShrOpExpr* bitShrOpExpr(
		BitShrOpExpr::create(
			addOpExpr,
			varD
	));
	BitAndOpExpr* bitAndOpExpr(
		BitAndOpExpr::create(
			bitShrOpExpr,
			varE
	));
	BitXorOpExpr* bitXorOpExpr(
		BitXorOpExpr::create(
			bitAndOpExpr,
			varF
	));
	BitOrOpExpr* bitOrOpExpr(
		BitOrOpExpr::create(
			bitXorOpExpr,
			varG
	));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			bitOrOpExpr,
			varH
	));
	AndOpExpr* andOpExpr(
		AndOpExpr::create(
			eqOpExpr,
			varI
	));
	OrOpExpr* orOpExpr(
		OrOpExpr::create(
			andOpExpr,
			varJ
	));
	ReturnStmt* returnStmt(ReturnStmt::create(orOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	Variable* varD(Variable::create("d", IntType::create(16)));
	Variable* varE(Variable::create("e", IntType::create(16)));
	Variable* varF(Variable::create("f", IntType::create(16)));
	Variable* varG(Variable::create("g", IntType::create(16)));
	Variable* varH(Variable::create("h", IntType::create(16)));
	Variable* varI(Variable::create("i", IntType::create(16)));
	Variable* varJ(Variable::create("j", IntType::create(16)));
	OrOpExpr* orOpExpr(
		OrOpExpr::create(
			varA,
			varB
	));
	AndOpExpr* andOpExpr(
		AndOpExpr::create(
			orOpExpr,
			varC
	));
	NeqOpExpr* neqOpExpr(
		NeqOpExpr::create(
			andOpExpr,
			varD
	));
	BitOrOpExpr* bitOrOpExpr(
		BitOrOpExpr::create(
			neqOpExpr,
			varE
	));
	BitXorOpExpr* bitXorOpExpr(
		BitXorOpExpr::create(
			bitOrOpExpr,
			varF
	));
	BitAndOpExpr* bitAndOpExpr(
		BitAndOpExpr::create(
			bitXorOpExpr,
			varG
	));
	BitShlOpExpr* bitShlOpExpr(
		BitShlOpExpr::create(
			bitAndOpExpr,
			varH
	));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			bitShlOpExpr,
			varI
	));
	DivOpExpr* divOpExpr(
		DivOpExpr::create(
			addOpExpr,
			varJ
	));
	AddressOpExpr* addressOpExpr(
		AddressOpExpr::create(
			divOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(addressOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varA,
			varB
	));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varB,
			varC
	));
	TernaryOpExpr* ternaryOpExpr(
		TernaryOpExpr::create(
			ltOpExpr,
			varA,
			addOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(ternaryOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varA,
			varB
	));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varB,
			varC
	));
	TernaryOpExpr* ternaryOpExpr(
		TernaryOpExpr::create(
			ltOpExpr,
			varA,
			addOpExpr
	));
	ModOpExpr* modOpExpr(
		ModOpExpr::create(
			ternaryOpExpr,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(modOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	Variable* varC(Variable::create("c", IntType::create(16)));
	LtOpExpr* ltOpExpr(
		LtOpExpr::create(
			varA,
			varB
	));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varB,
			varC
	));
	TernaryOpExpr* ternaryOpExpr(
		TernaryOpExpr::create(
			ltOpExpr,
			varA,
			addOpExpr
	));
	ModOpExpr* modOpExpr(
		ModOpExpr::create(
			ConstInt::create(5, 64),
			ternaryOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(modOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	IntToPtrCastExpr* intToPtrCastExpr(
		IntToPtrCastExpr::create(
			varA,
			IntType::create(16)
	));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			intToPtrCastExpr,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(addOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	IntToPtrCastExpr* intToPtrCastExpr(
		IntToPtrCastExpr::create(
			addOpExpr,
			IntType::create(16)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(intToPtrCastExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	IntToPtrCastExpr* intToPtrCastExpr(
		IntToPtrCastExpr::create(
			varA,
			IntType::create(16)
	));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			intToPtrCastExpr,
			ConstInt::create(1, 32)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(arrayIndexOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	IntToPtrCastExpr* intToPtrCastExpr(
		IntToPtrCastExpr::create(
			varA,
			IntType::create(16)
	));
	StructIndexOpExpr* structIndexOpExpr(
		StructIndexOpExpr::create(
			intToPtrCastExpr,
			ConstInt::create(1, 32)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(structIndexOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	args.push_back(addOpExpr);
	CallExpr* callExpr(
		CallExpr::create(
			varA,
			args
	));
	ReturnStmt* returnStmt(ReturnStmt::create(callExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	args.push_back(subOpExpr);
	CallExpr* callExpr(
		CallExpr::create(
			varA,
			args
	));
	MulOpExpr* mulOpExpr(
		MulOpExpr::create(
			varA,
			callExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(mulOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	CallExpr* callExpr(
		CallExpr::create(
			arrayIndexOpExpr,
			ExprVector()
	));
	ReturnStmt* returnStmt(ReturnStmt::create(callExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	BitCastExpr* castExpr(
		BitCastExpr::create(
			varA,
			IntType::create(32)
	));
	CallExpr* callExpr(
		CallExpr::create(
			castExpr,
			ExprVector()
	));
	ReturnStmt* returnStmt(ReturnStmt::create(callExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	DerefOpExpr* derefOpExpr(
		DerefOpExpr::create(varA)
	);
	CallExpr* callExpr(
		CallExpr::create(
			derefOpExpr,
			ExprVector()
	));
	ReturnStmt* returnStmt(ReturnStmt::create(callExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			addOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(arrayIndexOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(arrayIndexOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ArrayIndexOpExpr* arrayIndexOpExpr(
		ArrayIndexOpExpr::create(
			varA,
			subOpExpr
	));
	MulOpExpr* mulOpExpr(
		MulOpExpr::create(
			varA,
			arrayIndexOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(mulOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	StructIndexOpExpr* structIndexOpExpr(
		StructIndexOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	MulOpExpr* mulOpExpr(
		MulOpExpr::create(
			varA,
			structIndexOpExpr
	));

	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			mulOpExpr,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(addOpExpr));
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	StructIndexOpExpr* structIndexOpExpr(
		StructIndexOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(structIndexOpExpr));
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
