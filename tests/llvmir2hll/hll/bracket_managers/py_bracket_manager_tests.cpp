/**
* @file tests/llvmir2hll/hll/bracket_managers/py_bracket_manager_tests.cpp
* @brief Tests for the @c py_bracket_manager module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/hll/bracket_managers/py_bracket_manager.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
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
* @brief Tests for the @c py_bracket_manager module.
*/
class PyBracketManagerTests: public TestsWithModule {};

TEST_F(PyBracketManagerTests,
ManagerHasNonEmptyID) {
	PyBracketManager pyBrackets(module);

	EXPECT_TRUE(!pyBrackets.getId().empty()) <<
		"the manager should have a non-empty ID";
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_TRUE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr1)) <<
		"not expected brackets around " << mulOpExpr1;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr2)) <<
		"not expected brackets around " << mulOpExpr2;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"expected brackets around " << mulOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExprABC)) <<
		"not expected brackets around " << divOpExprABC;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(divOpExprBC)) <<
		"expected brackets around " << divOpExprBC;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExprAB)) <<
		"not expected brackets around " << divOpExprABC;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExprABC)) <<
		"not expected brackets around " << divOpExprABC;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(notOpExpr)) <<
		"not expected brackets around " << notOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
}

TEST_F(PyBracketManagerTests,
EqNotBracketsNeeded) {
	// return (a == (!b));
	//
	// expected output: return a == (!b);
	// because python don't have construction like a == not b;
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
	PyBracketManager pyBrackets(module);

	EXPECT_TRUE(pyBrackets.areBracketsNeeded(notOpExpr)) <<
		"expected brackets around " << notOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
}

TEST_F(PyBracketManagerTests,
NotEqGtEqGtLtEqLtNeqBracketsAreNotNeeded) {
	// return (((((((!a) == b) >= c) > d) <= e) < f) != g);
	//
	// expected output: return !a == b >= c > d <= f < g != h;
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(notOpExpr)) <<
		"not expected brackets around " << notOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(gtEqOpExpr)) <<
		"not expected brackets around " << gtEqOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(gtOpExpr)) <<
		"not expected brackets around " << gtOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(ltEqOpExpr)) <<
		"not expected brackets around " << ltEqOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(neqOpExpr)) <<
		"not expected brackets around " << neqOpExpr;
}

TEST_F(PyBracketManagerTests,
NotEqGtEqGtLtEqLtNeqBracketsAreNeeded) {
	// return (!(a == (b >= (c > (d <= (e < (f != g))))));
	//
	// expected output: return !a == (b >= (c > (d <= (e < (f != g))));
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(notOpExpr)) <<
		"expected brackets around " << notOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(eqOpExpr)) <<
		"expected brackets around " << eqOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(gtEqOpExpr)) <<
		"expected brackets around " << gtEqOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(gtOpExpr)) <<
		"expected brackets around " << gtOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(ltEqOpExpr)) <<
		"expected brackets around " << ltEqOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(ltOpExpr)) <<
		"expected brackets around " << ltOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(neqOpExpr)) <<
		"expected brackets around " << neqOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExprBC)) <<
		"not expected brackets around " << addOpExprBC;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(subOpExprAB)) <<
		"not expected brackets around " << subOpExprAB;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExprBCAB)) <<
		"not expected brackets around " << addOpExprBCAB;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(divOpExpr)) <<
		"not expected brackets around " << divOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(addOpExprABCAB)) <<
		"expected brackets around " << addOpExprABCAB;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(negOpExpr)) <<
		"not expected brackets around " << negOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(derefOpExpr)) <<
		"not expected brackets around " << derefOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addressOpExpr)) <<
		"not expected brackets around " << addressOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(addressOpExpr)) <<
		"expected brackets around " << addressOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(arrayIndexOpExpr)) <<
		"not expected brackets around " << arrayIndexOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(andOpExpr)) <<
		"not expected brackets around " << andOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(derefOpExpr)) <<
		"not expected brackets around " << derefOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addressOpExpr)) <<
		"not expected brackets around " << addressOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(ltEqOpExpr)) <<
		"expected brackets around " << ltEqOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(gtOpExpr)) <<
		"expected brackets around " << gtOpExpr;
}

TEST_F(PyBracketManagerTests,
OneOperatorFromOnePrecedenceRowBracketsNotNeeded) {
	// return ((((((((((*a) % b) + c) >> d) & e) ^ f) | g) == h) && i) || j);
	//
	// expected output: return *a % b + c >> d & e ^ f | g == h && i || j;
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(derefOpExpr)) <<
		"not expected brackets around " << derefOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(modOpExpr)) <<
		"not expected brackets around " << modOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(bitShrOpExpr)) <<
		"not expected brackets around " << bitShrOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(bitAndOpExpr)) <<
		"not expected brackets around " << bitAndOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(bitXorOpExpr)) <<
		"not expected brackets around " << bitXorOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(bitOrOpExpr)) <<
		"not expected brackets around " << bitOrOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(eqOpExpr)) <<
		"not expected brackets around " << eqOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(andOpExpr)) <<
		"not expected brackets around " << andOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(orOpExpr)) <<
		"not expected brackets around " << orOpExpr;
}

TEST_F(PyBracketManagerTests,
OneOperatorFromOnePrecedenceRowBracketsNeeded) {
	// return ((((((((((a || b) && c) != d) | e) ^ f) & g) << h) + i) / j)&);
	//
	// expected output: return (((((((((a || b) && c) != d) | e) ^
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
	PyBracketManager pyBrackets(module);

	EXPECT_TRUE(pyBrackets.areBracketsNeeded(orOpExpr)) <<
		"expected brackets around " << orOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(andOpExpr)) <<
		"expected brackets around " << andOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(neqOpExpr)) <<
		"expected brackets around " << neqOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(bitOrOpExpr)) <<
		"expected brackets around " << bitOrOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(bitXorOpExpr)) <<
		"expected brackets around " << bitXorOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(bitAndOpExpr)) <<
		"expected brackets around " << bitAndOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(bitShlOpExpr)) <<
		"expected brackets around " << bitShlOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(divOpExpr)) <<
		"expected brackets around " << divOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addressOpExpr)) <<
		"not expected brackets around " << addressOpExpr;
}

TEST_F(PyBracketManagerTests,
TernaryOpBracketsAreNotNeeded) {
	// return (a if (a < b) else (b + c));
	//
	// expected output: return a if a < b else b + c;
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(ternaryOpExpr)) <<
		"not expected brackets around " << ternaryOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
}

TEST_F(PyBracketManagerTests,
TernaryOpBracketsAreNeededFalseCond) {
	// return (a if (a < b) else (b + c)) % 2;
	//
	// expected output: return (a if a < b else b + c) % 2;
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(modOpExpr)) <<
		"not expected brackets around " << modOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(ternaryOpExpr)) <<
		"expected brackets around " << ternaryOpExpr;
}

TEST_F(PyBracketManagerTests,
TernaryOpBracketsAreNeededTrueCond) {
	// return 5 % (a if (a < b) else (b + c));
	//
	// expected output: return 5 % (a if a < b else b + c);
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(ltOpExpr)) <<
		"not expected brackets around " << ltOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(modOpExpr)) <<
		"not expected brackets around " << modOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(ternaryOpExpr)) <<
		"expected brackets around " << ternaryOpExpr;
}

TEST_F(PyBracketManagerTests,
NotSupportedOperatorBracketsNeededInsideExpr) {
	// return IntToPtrCastExpr(b*(a + 2));
	//
	// expected output: return b*(a + 2);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varB,
			addOpExpr
	));
	ShPtr<IntToPtrCastExpr> intToPtrCastExpr(
		IntToPtrCastExpr::create(
			mulOpExpr,
			IntType::create(16)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(intToPtrCastExpr));
	testFunc->setBody(returnStmt);
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
}

TEST_F(PyBracketManagerTests,
NotSupportedOperatorBracketsNeededCast) {
	// return b*IntToPtrCastExpr(a + 2);
	//
	// expected output: return b*(a + 2);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
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
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varB,
			intToPtrCastExpr
	));

	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
	EXPECT_TRUE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"expected brackets around " << addOpExpr;
}

TEST_F(PyBracketManagerTests,
CallExprWithArgumentsBracketsNotNeeded) {
	// return varA(a + 2);
	//
	// For this purpose is calledExpr substitute with Variable. This is only
	// for make simplifier function and have no effect on result.
	//
	// expected output: return varA(a + 2);
	//
	ExprVector exprList;
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	exprList.push_back(addOpExpr);
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			varA,
			exprList
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(callExpr));
	testFunc->setBody(returnStmt);
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
}

TEST_F(PyBracketManagerTests,
CallExprInExpressionWithArgumentsBracketsNotNeeded) {
	// return a * varA(a - 2);
	//
	// For this purpose is calledExpr substitute with Variable. This is only
	// for make simplifier function and have no effect on result.
	//
	// expected output: return a * varA(a - 2);
	//
	ExprVector exprList;
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	exprList.push_back(subOpExpr);
	ShPtr<CallExpr> callExpr(
		CallExpr::create(
			varA,
			exprList
	));
	ShPtr<MulOpExpr> mulOpExpr(
		MulOpExpr::create(
			varA,
			callExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(mulOpExpr));
	testFunc->setBody(returnStmt);
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(subOpExpr)) <<
		"not expected brackets around " << subOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(callExpr)) <<
		"not expected brackets around " << callExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(arrayIndexOpExpr)) <<
		"not expected brackets around " << arrayIndexOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_TRUE(pyBrackets.areBracketsNeeded(derefOpExpr)) <<
		"expected brackets around " << derefOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(subOpExpr)) <<
		"not expected brackets around " << subOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(arrayIndexOpExpr)) <<
		"not expected brackets around " << arrayIndexOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(addOpExpr)) <<
		"not expected brackets around " << addOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(varA)) <<
		"not expected brackets around " << varA;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_TRUE(pyBrackets.areBracketsNeeded(assignOpExpr)) <<
		"expected brackets around " << assignOpExpr;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(mulOpExpr)) <<
		"not expected brackets around " << mulOpExpr;
}

TEST_F(PyBracketManagerTests,
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
	PyBracketManager pyBrackets(module);

	EXPECT_FALSE(pyBrackets.areBracketsNeeded(assignABC)) <<
		"not expected brackets around " << assignABC;
	EXPECT_FALSE(pyBrackets.areBracketsNeeded(assignBC)) <<
		"not expected brackets around " << assignBC;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
