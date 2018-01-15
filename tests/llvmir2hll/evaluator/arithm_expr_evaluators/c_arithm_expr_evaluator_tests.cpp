/**
* @file tests/llvmir2hll/evaluator/arithm_expr_evaluators/c_arithm_expr_evaluator_tests.cpp
* @brief Tests for the @c c_arithm_expr_evaluator module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/c_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

using VarConstMap = std::map<ShPtr<Variable>, ShPtr<Constant>>;

/**
* @brief Tests for the @c c_arithm_expr_evaluator module.
*/
class CArithmExprEvaluatorTests: public TestsWithModule {
protected:
	void evaluateAndCheckResult(ShPtr<Expression> inputExpr,
		ShPtr<Expression> refResult);
	void evaluateAndCheckResult(ShPtr<Expression> inputExpr,
		ShPtr<Expression> refResult, VarConstMap varConstMap);
};

/**
* @brief Evaluate @a inputExpr and result compare with @a refResult.
*
* @param[in] inputExpr An expression to evaluation.
* @param[in] refResult An expression to compare with the @a inputExpr.
*/
void CArithmExprEvaluatorTests::evaluateAndCheckResult(
		ShPtr<Expression> inputExpr, ShPtr<Expression> refResult) {
	evaluateAndCheckResult(inputExpr, refResult, VarConstMap());
}

/**
* @brief Evaluate @a inputExpr and result compare with @a refResult. Also
*        substitute variables with constants from @a varConstMap.
*
* @param[in] inputExpr An expression to evaluation.
* @param[in] refResult An expression to compare with the @a inputExpr.
* @param[in] varConstMap map of constants to substitute the variables in @a inputExpr.
*/
void CArithmExprEvaluatorTests::evaluateAndCheckResult(
		ShPtr<Expression> inputExpr, ShPtr<Expression> refResult,
		VarConstMap varConstMap) {
	ShPtr<ArithmExprEvaluator> evaluator(CArithmExprEvaluator::create());
	ShPtr<Constant> result(evaluator->evaluate(inputExpr, varConstMap));
	if (refResult && !result) {
		FAIL() << "expected `" << refResult << "`, " <<
			"but the expression was not evaluated";
	} else if (!refResult && result) {
		FAIL() << "expected the expression not to be evaluated, " <<
			"but it was evaluated to `" << result;
	} else if (!refResult && !result) {
		// The null pointer was expected and returned.
	} else {
		EXPECT_TRUE(refResult->isEqualTo(result)) <<
			"expected `" << refResult << "`, " <<
			"got `" << result << "`";
	}
}

TEST_F(CArithmExprEvaluatorTests,
EvaluatorHasNonEmptyID) {
	ShPtr<ArithmExprEvaluator> evaluator(CArithmExprEvaluator::create());
	EXPECT_TRUE(!evaluator->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operators or operands, when evaluating must be stopped
//

TEST_F(CArithmExprEvaluatorTests,
AddNumConstIntAddressTest) {
	SCOPED_TRACE("2 + &a   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		AddressOpExpr::create(varA)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
AddNumConstIntArrayIndexOpExprTest) {
	SCOPED_TRACE("2 + a[2]   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		ArrayIndexOpExpr::create(varA, ConstInt::create(2, 64))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
AddNumConstIntStructIndexOpExprTest) {
	SCOPED_TRACE("2 + StructIndexOpExpr   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		StructIndexOpExpr::create(varA, ConstInt::create(2, 64))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
AddNumConstIntDerefOpExprTest) {
	SCOPED_TRACE("2 + *2  ->   Not evaluated");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		DerefOpExpr::create(ConstInt::create(2, 64))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntCallOpExprTest) {
	ExprVector args;
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * callExpr  ->   Not evaluated");
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		CallExpr::create(varA, args)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntExtCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * ExtCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<ExtCastExpr> cast(ExtCastExpr::create(
		varA,
		IntType::create(32)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntTruncCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * TruncCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<TruncCastExpr> cast(TruncCastExpr::create(
		varA,
		IntType::create(32)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntIntToPtrCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * IntToPtrCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<IntToPtrCastExpr> cast(IntToPtrCastExpr::create(
		varA,
		IntType::create(32)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntPtrToIntCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * PtrToIntCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<PtrToIntCastExpr> cast(PtrToIntCastExpr::create(
		varA,
		IntType::create(32)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntConstNullPointerTest) {
	SCOPED_TRACE("2 * ConstNullPointer(IntType)  ->   Not evaluated");
	ShPtr<ConstNullPointer> pointer(ConstNullPointer::create(
		PointerType::create(IntType::create(32))));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		pointer
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntConstStringTest) {
	SCOPED_TRACE("2 * ConstString()  ->   Not evaluated");
	ShPtr<ConstString> constString(ConstString::create(""));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		constString
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntConstArrayTest) {
	SCOPED_TRACE("2 * ConstArray()  ->   Not evaluated");
	ShPtr<ConstArray> constArray(ConstArray::createUninitialized(
		ArrayType::create(IntType::create(32), ArrayType::Dimensions())
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		constArray
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntConstStructTest) {
	SCOPED_TRACE("2 * ConstStruct()  ->   Not evaluated");
	ShPtr<ConstStruct> constStruct(ConstStruct::create(
		ConstStruct::Type(), StructType::create(StructType::ElementTypes())));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		constStruct
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstIntVariableTest) {
	SCOPED_TRACE("2 * varA  ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		varA
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

//
// Tests for special conditions when CArithmExprEvaluator must stop
// evaluation.
//

TEST_F(CArithmExprEvaluatorTests,
DivNumConstIntNumConstIntZeroDivTest) {
	SCOPED_TRACE("3 / 0 ->   Not evaluated");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(0, 64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
ModNumConstIntNumConstIntZeroModTest) {
	SCOPED_TRACE("3 % 0 ->   Not evaluated");
	ShPtr<ModOpExpr> inputExpr(ModOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(0, 64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
BitXorOnConstFloatTest) {
	SCOPED_TRACE("1.0 ^ 2.0   ->   Not evaluated");
	ShPtr<BitXorOpExpr> inputExpr(BitXorOpExpr::create(
		ConstFloat::create(llvm::APFloat(1.0)),
		ConstFloat::create(llvm::APFloat(2.0))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntIntToFPCastExprIntTypeTest) {
	SCOPED_TRACE("IntToFPCastExpr(2(ConstInt), IntType)  ->   Not evaluated");
	ShPtr<IntToFPCastExpr> inputExpr(IntToFPCastExpr::create(
		ConstInt::create(2, 64),
		IntType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstFloatIntToFPCastExprIntTypeTest) {
	SCOPED_TRACE("IntToFPCastExpr(2.0(ConstFloat), FloatType)  ->   Not evaluated");
	ShPtr<IntToFPCastExpr> inputExpr(IntToFPCastExpr::create(
		ConstFloat::create(llvm::APFloat(2.0)),
		FloatType::create(64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstFloatFPToIntCastExprFloatTypeTest) {
	SCOPED_TRACE("FPToIntCastExpr(2.0, FloatType)  ->   Not evaluated");
	ShPtr<FPToIntCastExpr> inputExpr(FPToIntCastExpr::create(
		ConstFloat::create(llvm::APFloat(2.0)),
		FloatType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
FPToIntCastExprInfinityTest) {
	SCOPED_TRACE("FPToIntCastExpr(+inf, IntType(32 - bitWidth))  ->"
		"   Not evaluated");
	llvm::APFloat refF(0.0);
	const llvm::fltSemantics &refSemantics(refF.getSemantics());
	ShPtr<ConstFloat> constFloat(ConstFloat::create(llvm::APFloat::getInf(
		refSemantics)));
	ShPtr<FPToIntCastExpr> inputExpr(FPToIntCastExpr::create(
		constFloat,
		IntType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstFloatFloatTypeExtCastExprTest) {
	SCOPED_TRACE("ExtCastExpr(2.0, FloatType)  ->   Not evaluated");
	ShPtr<ExtCastExpr> inputExpr(ExtCastExpr::create(
		ConstFloat::create(llvm::APFloat(2.0)),
		FloatType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntIntTypeLowerBitWidthExtCastExprTest) {
	SCOPED_TRACE("ExtCastExpr(2(64 - bits), IntType(32))  ->   Not evaluated");
	ShPtr<ExtCastExpr> inputExpr(ExtCastExpr::create(
		ConstInt::create(2, 64),
		IntType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntIntTypeSameBitWidthExtCastExprTest) {
	SCOPED_TRACE("ExtCastExpr(2(32 - bits), IntType(32))  ->   Not evaluated");
	ShPtr<ExtCastExpr> inputExpr(ExtCastExpr::create(
		ConstInt::create(2, 32),
		IntType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstBoolIntTypeSameBitWidthExtCastExprTest) {
	SCOPED_TRACE("ExtCastExpr(true(1 bit), IntType(1))  ->   Not evaluated");
	ShPtr<ExtCastExpr> inputExpr(ExtCastExpr::create(
		ConstBool::create(true),
		IntType::create(1)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstFloatFloatTypeTruncCastExprTest) {
	SCOPED_TRACE("TruncCastExpr(2.0, FloatType)  ->   Not evaluated");
	ShPtr<TruncCastExpr> inputExpr(TruncCastExpr::create(
		ConstFloat::create(llvm::APFloat(2.0)),
		FloatType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntTypeHigherBitWidthTruncCastTest) {
	SCOPED_TRACE("TruncCastExpr(2(32 - bits), IntType(64))  ->   Not evaluated");
	ShPtr<TruncCastExpr> inputExpr(TruncCastExpr::create(
		ConstInt::create(2, 32),
		IntType::create(64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntTypeSameBitWidthTruncCastTest) {
	SCOPED_TRACE("TruncCastExpr(2(32 - bits), IntType(32))  ->   Not evaluated");
	ShPtr<TruncCastExpr> inputExpr(TruncCastExpr::create(
		ConstInt::create(2, 32),
		IntType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntBitCastExprFloatTypeTest) {
	SCOPED_TRACE("BitCastExpr(2, FloatType)  ->   Not evaluated");
	ShPtr<BitCastExpr> inputExpr(BitCastExpr::create(
		ConstInt::create(2, 64),
		FloatType::create(32)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

//
// Tests for expressions that can be evaluated.
//

TEST_F(CArithmExprEvaluatorTests,
OnlyConstIntTest) {
	SCOPED_TRACE("2   ->   2");
	ShPtr<ConstInt> inputExpr(ConstInt::create(2, 64));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NotOpExprConstIntFalseTest) {
	SCOPED_TRACE("!2   ->   false");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstInt::create(2, 64)));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NotOpExprConstIntTrueTest) {
	SCOPED_TRACE("!0   ->   true");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstInt::create(0, 64)));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NotOpExprConstFloatTrueTest) {
	SCOPED_TRACE("!0.0   ->   true");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstFloat::create(llvm::APFloat(0.0))));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NotOpExprConstFloatFalseTest) {
	SCOPED_TRACE("!0.1   ->   false");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstFloat::create(llvm::APFloat(0.1))));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NegOpExprTest) {
	SCOPED_TRACE("-2(negOpExpr)   ->   2");
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(
		ConstInt::create(-2, 64, true)));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64, true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NegOpExprMinSignedValueTest) {
	SCOPED_TRACE("-128(8 bits) ->   -128(8 bits)");
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(
		ConstInt::create(-128, 8, true)
	));

	ShPtr<ConstInt> refResult(ConstInt::create(-128, 8, true));
	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NegOpExprConstBoolTest) {
	SCOPED_TRACE("-true ->   -1");
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(
		ConstBool::create(true)
	));

	ShPtr<ConstInt> refResult(ConstInt::create(-1, 32, true));
	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
EqOpExprConstIntTest) {
	SCOPED_TRACE("2 == 3   ->   false");
	ShPtr<EqOpExpr> inputExpr(EqOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
EqOpExprConstBoolTest) {
	SCOPED_TRACE("true == true   ->   true");
	ShPtr<EqOpExpr> inputExpr(EqOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(true)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NeqOpExprConstBoolTest) {
	SCOPED_TRACE("false != true   ->   true");
	ShPtr<NeqOpExpr> inputExpr(NeqOpExpr::create(
		ConstBool::create(false),
		ConstBool::create(true)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
GtOpExprConstIntTrueTest) {
	SCOPED_TRACE("3 > 2   ->   true");
	ShPtr<GtOpExpr> inputExpr(GtOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
GtOpExprConstIntFalseTest) {
	SCOPED_TRACE("2 > 3   ->   false");
	ShPtr<GtOpExpr> inputExpr(GtOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
GtOpExprConstBoolTrueTest) {
	SCOPED_TRACE("true > false   ->   true");
	ShPtr<GtOpExpr> inputExpr(GtOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(false)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
LtOpExprConstIntTrueTest) {
	SCOPED_TRACE("2 < 3   ->   true");
	ShPtr<LtOpExpr> inputExpr(LtOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
LtOpExprConstIntFalseTest) {
	SCOPED_TRACE("3 < 2   ->   true");
	ShPtr<LtOpExpr> inputExpr(LtOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
LtEqOpExprConstIntNotEqualTrue) {
	SCOPED_TRACE("2 <= 3   ->   true");
	ShPtr<LtEqOpExpr> inputExpr(LtEqOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
LtEqOpExprConstIntEqualTrueTest) {
	SCOPED_TRACE("3 <= 3   ->   true");
	ShPtr<LtEqOpExpr> inputExpr(LtEqOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
GtEqOpExprConstIntNotEqualTrue) {
	SCOPED_TRACE("3 >= 2   ->   true");
	ShPtr<GtEqOpExpr> inputExpr(GtEqOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
GtEqOpExprConstIntEqualTrueTest) {
	SCOPED_TRACE("3 >= 3   ->   true");
	ShPtr<GtEqOpExpr> inputExpr(GtEqOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddTest) {
	SCOPED_TRACE("2 + 2   ->   4");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddConstBoolTest) {
	SCOPED_TRACE("true + true   ->   2");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(true)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 32));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddConstIntConstBoolTest) {
	SCOPED_TRACE("2 + false   ->   2");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 32),
		ConstBool::create(false)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 32));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddConstIntConstFloatTest) {
	SCOPED_TRACE("2 + 1.2   ->   3.2");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		ConstFloat::create(llvm::APFloat(1.2))
	));
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat(3.2)));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SubNumConstIntNumConstIntNotSameBitWidthTest) {
	SCOPED_TRACE("2(4 bitWidth) - 4(8 bitWidth)  ->   -2(8 bitWidth)");
	ShPtr<SubOpExpr> inputExpr(SubOpExpr::create(
		ConstInt::create(2, 4),
		ConstInt::create(4, 8)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(-2, 8));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddUnsignedSignedTest) {
	SCOPED_TRACE("2(unsigned) + 2(signed)   ->   4(unsigned)");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64, false),
		ConstInt::create(2, 64, true)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4, 64, false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddSignedLowerBitWidthUnsignedDiffBitWidthTest) {
	SCOPED_TRACE("2(signed - 32 bitWidth) + 2(unsigned - 64 bitWidth)   ->"
		"   4(unsigned - 64 bitWidth)");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 32, true),
		ConstInt::create(2, 64, false)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4, 64, false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddUnsignedLowerBitWidthSignedDiffBitWidthResultSignedTest) {
	SCOPED_TRACE("2(unsigned - 32 bitWidth) + 2(signed - 64 bitWidth)   ->"
		"   4(signed - 64 bitWidth)");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 32, false),
		ConstInt::create(2, 64, true)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4, 64, true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SubNumConstIntNumConstIntSignedUnsignedTypeTest) {
	SCOPED_TRACE("2(signed) - 4(unsigned)  ->   -2");
	ShPtr<SubOpExpr> inputExpr(SubOpExpr::create(
		ConstInt::create(2, 32, true),
		ConstInt::create(4, 32, false)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4294967294u, 32, false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAddDiffAPFloatSemanticsTest) {
	SCOPED_TRACE("2.0(IEEEhalf) + 4.0(IEEEdouble)   ->   6.0(IEEEdouble)");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstFloat::create(llvm::APFloat(llvm::APFloat::IEEEhalf, "2.0")),
		ConstFloat::create(llvm::APFloat(llvm::APFloat::IEEEdouble, "4.0"))
	));
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat(
		llvm::APFloat::IEEEdouble, "6.0")));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
AddNumConstIntNumConstIntOverflowTest) {
	SCOPED_TRACE("7(4 bits) + 7(4 bits) ->   -2(4 bits)");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(7, 4),
		ConstInt::create(7, 4)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(-2, 4, true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
MoreAddTest) {
	SCOPED_TRACE("(3 + 5) + (2 + 1) -> 11");
	ShPtr<AddOpExpr> leftAdd(
	AddOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(5, 64)
	));
	ShPtr<AddOpExpr> rightAdd(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(1, 64)
	));
	ShPtr<AddOpExpr> centralAdd(
		AddOpExpr::create(
			leftAdd,
			rightAdd
	));
	ShPtr<ConstInt> refResult(ConstInt::create(11, 64));

	evaluateAndCheckResult(centralAdd, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
MoreSubTest) {
	SCOPED_TRACE("(3 - 5) - (2 - 1) -> -3");
	ShPtr<SubOpExpr> leftAdd(
	SubOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(5, 64)
	));
	ShPtr<SubOpExpr> rightAdd(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(1, 64)
	));
	ShPtr<SubOpExpr> centralAdd(
		SubOpExpr::create(
			leftAdd,
			rightAdd
	));
	ShPtr<ConstInt> refResult(ConstInt::create(-3, 64, true));

	evaluateAndCheckResult(centralAdd, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleMulTest) {
	SCOPED_TRACE("3 * 2   ->   6");
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(6, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleModTest) {
	SCOPED_TRACE("6 % 2   ->   0");
	ShPtr<ModOpExpr> inputExpr(ModOpExpr::create(
		ConstInt::create(6, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(0, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleDivTest) {
	SCOPED_TRACE("6 / 3   ->   2");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(6, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(3, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
DivNumConstIntNumConstIntRemainderTest) {
	SCOPED_TRACE("3 / 2 ->   1");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(1, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
DivPositiveZeroFloatTest) {
	SCOPED_TRACE("6.0 / 0.0   ->   +inf");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstFloat::create(llvm::APFloat(6.0)),
		ConstFloat::create(llvm::APFloat(0.0))
	));
	llvm::APFloat refF(0.0);
	const llvm::fltSemantics &refSemantics(refF.getSemantics());
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat::getInf(
		refSemantics)));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
DivNegativeZeroFloatTest) {
	SCOPED_TRACE("6.0 / -0.0   ->   -inf");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstFloat::create(llvm::APFloat(6.0)),
		ConstFloat::create(llvm::APFloat(-0.0))
	));
	llvm::APFloat refF(0.0);
	const llvm::fltSemantics &refSemantics(refF.getSemantics());
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat::getInf(
		refSemantics, true)));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAndTrueTest) {
	SCOPED_TRACE("true && true   ->   true");
	ShPtr<AndOpExpr> inputExpr(AndOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(true)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleAndFalseTest) {
	SCOPED_TRACE("1 && 0   ->   false");
	ShPtr<AndOpExpr> inputExpr(AndOpExpr::create(
		ConstInt::create(1, 64),
		ConstInt::create(0, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleOrTrueTest) {
	SCOPED_TRACE("true || false   ->   true");
	ShPtr<OrOpExpr> inputExpr(OrOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(false)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleOrFalseTest) {
	SCOPED_TRACE("0 && 0   ->   false");
	ShPtr<AndOpExpr> inputExpr(AndOpExpr::create(
		ConstFloat::create(llvm::APFloat(0.0)),
		ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleBitAndTest) {
	SCOPED_TRACE("2 & 3   ->   2");
	ShPtr<BitAndOpExpr> inputExpr(BitAndOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleBitOrTest) {
	SCOPED_TRACE("2 | 3   ->   3");
	ShPtr<BitOrOpExpr> inputExpr(BitOrOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(3, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleBitXorTest) {
	SCOPED_TRACE("2 ^ 3   ->   1");
	ShPtr<BitXorOpExpr> inputExpr(BitXorOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(1, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleBitShlTest) {
	SCOPED_TRACE("4 << 2   ->   16");
	ShPtr<BitShlOpExpr> inputExpr(BitShlOpExpr::create(
		ConstInt::create(4, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(16, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleBitShrArithmeticalTest) {
	SCOPED_TRACE("4 >> 2   ->   1");
	ShPtr<BitShrOpExpr> inputExpr(BitShrOpExpr::create(
		ConstInt::create(4, 64),
		ConstInt::create(2, 64),
		BitShrOpExpr::Variant::Arithmetical
	));
	ShPtr<ConstInt> refResult(ConstInt::create(1, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleBitShrLogicalTest) {
	SCOPED_TRACE("4 >> 2   ->   1");
	ShPtr<BitShrOpExpr> inputExpr(BitShrOpExpr::create(
		ConstInt::create(4, 64),
		ConstInt::create(2, 64),
		BitShrOpExpr::Variant::Logical
	));
	ShPtr<ConstInt> refResult(ConstInt::create(1, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleTernaryOpExprTrueTest) {
	SCOPED_TRACE("4 ? 2 : 3   ->   2");
	ShPtr<TernaryOpExpr> inputExpr(TernaryOpExpr::create(
		ConstInt::create(4, 64),
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
SimpleTernaryOpExprFalseTest) {
	SCOPED_TRACE("false ? 2 : 3   ->   3");
	ShPtr<TernaryOpExpr> inputExpr(TernaryOpExpr::create(
		ConstBool::create(false),
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(3, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
MoreComplicatedTest1) {
	SCOPED_TRACE("(((((3 + 4) - 5) * 2) / 2) ^ 4)    ->   6");
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(4, 64)
	));
	ShPtr<SubOpExpr> subOpExpr(SubOpExpr::create(
		addOpExpr,
		ConstInt::create(5, 64)
	));
	ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(
		subOpExpr,
		ConstInt::create(2, 64)
	));
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(
		mulOpExpr,
		ConstInt::create(2, 64)
	));
	ShPtr<BitXorOpExpr> inputExpr(BitXorOpExpr::create(
		divOpExpr,
		ConstInt::create(4, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(6, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
MoreComplicatedTest2) {
	SCOPED_TRACE("((((2.5 + 2.5) - 3.5) * 2.0) / 2.0)    ->   1.5");
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(
		ConstFloat::create(llvm::APFloat(2.5)),
		ConstFloat::create(llvm::APFloat(2.5))
	));
	ShPtr<SubOpExpr> subOpExpr(SubOpExpr::create(
		addOpExpr,
		ConstFloat::create(llvm::APFloat(3.5))
	));
	ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(
		subOpExpr,
		ConstFloat::create(llvm::APFloat(2.0))
	));
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		mulOpExpr,
		ConstFloat::create(llvm::APFloat(2.0))
	));
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat(1.5)));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
MoreComplicatedTest3) {
	SCOPED_TRACE("(2 << (2 ^ (5 | (3 & 4))))    ->   256");
	ShPtr<BitAndOpExpr> bitAndOpExpr(BitAndOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(4, 64)
	));
	ShPtr<BitOrOpExpr> bitOrOpExpr(BitOrOpExpr::create(
		ConstInt::create(5, 64),
		bitAndOpExpr
	));
	ShPtr<BitXorOpExpr> bitXorOpExpr(BitXorOpExpr::create(
		ConstInt::create(2, 64),
		bitOrOpExpr
	));
	ShPtr<BitShlOpExpr> inputExpr(BitShlOpExpr::create(
		ConstInt::create(2, 64),
		bitXorOpExpr
	));
	ShPtr<ConstInt> refResult(ConstInt::create(256, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

//
// Tests for expressions that contains variables. Can't be evaluated.
//

TEST_F(CArithmExprEvaluatorTests,
SimpleAddWithVarsNotSubstituteTest) {
	SCOPED_TRACE("a(2) + b   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	VarConstMap varConstMap;
	varConstMap[varA] = ConstInt::create(2, 64);
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		varA,
		varB
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>(), varConstMap);
}

TEST_F(CArithmExprEvaluatorTests,
DivZeroWithVarTest) {
	SCOPED_TRACE("7 / b(0)   ->   Not evaluated");
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	VarConstMap varConstMap;
	varConstMap[varB] = ConstInt::create(0, 64);
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(7, 64),
		varB
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>(), varConstMap);
}

//
// Tests for expressions that contains variables. Can be evaluated.
//

TEST_F(CArithmExprEvaluatorTests,
SimpleAddWithVarsTest) {
	SCOPED_TRACE("a(2) + b(4)   ->   6");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	VarConstMap varConstMap;
	varConstMap[varA] = ConstInt::create(2, 64);
	varConstMap[varB] = ConstInt::create(4, 64);
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		varA,
		varB
	));
	ShPtr<ConstInt> refResult(ConstInt::create(6, 64));

	evaluateAndCheckResult(inputExpr, refResult, varConstMap);
}

TEST_F(CArithmExprEvaluatorTests,
NegOpExprWithVarTest) {
	SCOPED_TRACE("a(negOpExpr)(2)   ->   -2");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	VarConstMap varConstMap;
	varConstMap[varA] = ConstInt::create(2, 64);
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(varA));
	ShPtr<ConstInt> refResult(ConstInt::create(-2, 64, true));

	evaluateAndCheckResult(inputExpr, refResult, varConstMap);
}

TEST_F(CArithmExprEvaluatorTests,
MoreComplicatedWithVarsTest) {
	SCOPED_TRACE("(((((3 + a(4)) - 5) * 2) / b(2)) ^ c(4))    ->   6");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16, true)));
	VarConstMap varConstMap;
	varConstMap[varA] = ConstInt::create(4, 64);
	varConstMap[varB] = ConstInt::create(2, 64);
	varConstMap[varC] = ConstInt::create(4, 64);
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(
		ConstInt::create(3, 64),
		varA
	));
	ShPtr<SubOpExpr> subOpExpr(SubOpExpr::create(
		addOpExpr,
		ConstInt::create(5, 64)
	));
	ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(
		subOpExpr,
		ConstInt::create(2, 64)
	));
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(
		mulOpExpr,
		varB
	));
	ShPtr<BitXorOpExpr> inputExpr(BitXorOpExpr::create(
		divOpExpr,
		varC
	));
	ShPtr<ConstInt> refResult(ConstInt::create(6, 64));

	evaluateAndCheckResult(inputExpr, refResult, varConstMap);
}

//
// Tests for expressions that contains casts. Can be evaluated.
//

TEST_F(CArithmExprEvaluatorTests,
FPToIntCastExprTest) {
	SCOPED_TRACE("FPToIntCastExpr(2.0, IntType(32 - bitWidth))  ->"
		"   2(32 - bitWidth)");
	ShPtr<FPToIntCastExpr> inputExpr(FPToIntCastExpr::create(
		ConstFloat::create(llvm::APFloat(2.0)),
		IntType::create(32)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 32));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
MulNumConstFloatFPToIntCastExprTest) {
	SCOPED_TRACE("2 * FPToIntCastExpr(2, IntType)  ->   4");
	ShPtr<FPToIntCastExpr> cast(FPToIntCastExpr::create(
		ConstFloat::create(llvm::APFloat(2.0)),
		IntType::create(48)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntIntToFPCastExprTest) {
	SCOPED_TRACE("IntToFPCastExpr(2(ConstInt), FloatType)  ->   2.0");
	ShPtr<IntToFPCastExpr> inputExpr(IntToFPCastExpr::create(
		ConstInt::create(2, 64),
		FloatType::create(32)
	));
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat(2.0)));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NumConstBoolIntToFPCastExprTest) {
	SCOPED_TRACE("IntToFPCastExpr(1(ConstBool), FloatType)  ->   1.0");
	ShPtr<IntToFPCastExpr> inputExpr(IntToFPCastExpr::create(
		ConstBool::create(true),
		FloatType::create(32)
	));
	ShPtr<ConstFloat> refResult(ConstFloat::create(llvm::APFloat(1.0)));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntExtCastExprToHigherBitWidthTest) {
	SCOPED_TRACE("ExtCastExpr(2(32 - bits), IntType(64))  ->   2(64 - bits)");
	ShPtr<ExtCastExpr> inputExpr(ExtCastExpr::create(
		ConstInt::create(2, 32),
		IntType::create(64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NumConstIntTruncCastExprToLowerBitWidthTest) {
	SCOPED_TRACE("TruncCastExpr(2(64 - bits), IntType(32))  ->   2(32 - bits)");
	ShPtr<TruncCastExpr> inputExpr(TruncCastExpr::create(
		ConstInt::create(2, 64),
		IntType::create(32)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 32));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(CArithmExprEvaluatorTests,
NumConstFloatBitCastExprToIntTypeTypeTest) {
	SCOPED_TRACE("BitCastExpr(4.0, IntType)  ->   evaluated");
	ShPtr<BitCastExpr> inputExpr(BitCastExpr::create(
		ConstFloat::create(llvm::APFloat(125.28)),
		IntType::create(32)
	));

	ShPtr<ArithmExprEvaluator> evaluator(CArithmExprEvaluator::create());
	ASSERT_TRUE(evaluator->evaluate(inputExpr)) <<
		"expected evaluated expression, "
		"but the expression was not evaluated";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
