/**
* @file tests/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator_tests.cpp
* @brief Tests for the @c strict_arithm_expr_evaluator module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
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

using VarConstMap = ArithmExprEvaluator::VarConstMap;

/**
* @brief Tests for the @c strict_arithm_expr_evaluator module.
*/
class StrictArithmExprEvaluatorTests: public TestsWithModule {
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
void StrictArithmExprEvaluatorTests::evaluateAndCheckResult(
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
void StrictArithmExprEvaluatorTests::evaluateAndCheckResult(
		ShPtr<Expression> inputExpr, ShPtr<Expression> refResult,
		VarConstMap varConstMap) {
	ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::create());
	ShPtr<Constant> result(evaluator->evaluate(inputExpr, varConstMap));
	if (refResult && !result) {
		FAIL() << "expected `" << refResult << "`, " <<
			"but the expression was not evaluated";
	} else if (!refResult && result) {
		FAIL() << "expected the expression not to be evaluated, " <<
			"but it was evaluated to `" << result << "`";
	} else if (!refResult && !result) {
		// The null pointer was expected and returned.
	} else {
		EXPECT_TRUE(refResult->isEqualTo(result)) <<
			"expected `" << refResult << "`, " <<
			"got `" << result << "`";
	}
}

TEST_F(StrictArithmExprEvaluatorTests,
EvaluatorHasNonEmptyID) {
	ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::create());
	EXPECT_TRUE(!evaluator->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operators or operands, when evaluating must be stopped
//

TEST_F(StrictArithmExprEvaluatorTests,
AddNumConstIntAddressTest) {
	SCOPED_TRACE("2 + &a   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		AddressOpExpr::create(varA)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
AddNumConstIntArrayIndexOpExprTest) {
	SCOPED_TRACE("2 + a[2]   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		ArrayIndexOpExpr::create(varA, ConstInt::create(2, 64))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
AddNumConstIntStructIndexOpExprTest) {
	SCOPED_TRACE("2 + StructIndexOpExpr   ->   Not evaluated");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		StructIndexOpExpr::create(varA, ConstInt::create(2, 64))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
AddNumConstIntDerefOpExprTest) {
	SCOPED_TRACE("2 + *2  ->   Not evaluated");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		DerefOpExpr::create(ConstInt::create(2, 64))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
MulNumConstIntBitCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * BitCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<BitCastExpr> cast(BitCastExpr::create(
		varA,
		IntType::create(32)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
MulNumConstIntFPToIntCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * FPToIntCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<FPToIntCastExpr> cast(FPToIntCastExpr::create(
		varA,
		IntType::create(32)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
MulNumConstIntIntToFPCastExprTest) {
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	SCOPED_TRACE("2 * IntToFPCastExpr(a, IntType)  ->   Not evaluated");
	ShPtr<IntToFPCastExpr> cast(IntToFPCastExpr::create(
		varA,
		FloatType::create(20)
	));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		cast
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
MulNumConstIntConstStringTest) {
	SCOPED_TRACE("2 * ConstString()  ->   Not evaluated");
	ShPtr<ConstString> constString(ConstString::create(""));
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(2, 64),
		constString
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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
// Tests for special conditions when StrictArithmExprEvaluator must stop
// evaluation.
//

TEST_F(StrictArithmExprEvaluatorTests,
NegOpExprTrueTest) {
	SCOPED_TRACE("-True(negOpExpr)   ->   Not evaluated");
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(ConstBool::create(true)));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
SubNumConstIntNumConstIntNotSameBitWidthTest) {
	SCOPED_TRACE("2(2 bitWidth) -4(4 bitWidth)  ->   Not evaluated");
	ShPtr<SubOpExpr> inputExpr(SubOpExpr::create(
		ConstInt::create(2, 2),
		ConstInt::create(4, 4)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
SubNumConstIntNumConstFloatNotSameTypesTest) {
	SCOPED_TRACE("2(ConstInt) -1.5(ConstFloat)  ->   Not evaluated");
	ShPtr<SubOpExpr> inputExpr(SubOpExpr::create(
		ConstInt::create(2, 64),
		ConstFloat::create(llvm::APFloat(1.5))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
SubNumConstIntConstBoolNotSameTypesTest) {
	SCOPED_TRACE("2(ConstInt) - true  ->   Not evaluated");
	ShPtr<SubOpExpr> inputExpr(SubOpExpr::create(
		ConstInt::create(2, 64),
		ConstBool::create(1)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
DivNumConstIntNumConstIntRemainderTest) {
	SCOPED_TRACE("3 / 2 ->   Not evaluated");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
NegOpExprMinSignedValueTest) {
	SCOPED_TRACE("-128(8 bits) ->   Not evaluated");
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(
		ConstInt::create(-128, 8, true)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
DivNumConstIntNumConstIntZeroDivTest) {
	SCOPED_TRACE("3 / 0 ->   Not evaluated");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(0, 64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
ModNumConstIntNumConstIntZeroModTest) {
	SCOPED_TRACE("3 % 0 ->   Not evaluated");
	ShPtr<ModOpExpr> inputExpr(ModOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(0, 64)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
AddNumConstIntNumConstIntOverflowTest) {
	SCOPED_TRACE("7(4 bits) + 7(4 bits) ->   Not evaluated");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(7, 4),
		ConstInt::create(7, 4)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
GtOpExprBoolComparisonTest) {
	SCOPED_TRACE("true > false   ->   Not evaluated");
	ShPtr<GtOpExpr> inputExpr(GtOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(false)
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

TEST_F(StrictArithmExprEvaluatorTests,
BitXorOnConstFloatTest) {
	SCOPED_TRACE("1.0 ^ 2.0   ->   Not evaluated");
	ShPtr<BitXorOpExpr> inputExpr(BitXorOpExpr::create(
		ConstFloat::create(llvm::APFloat(1.0)),
		ConstFloat::create(llvm::APFloat(2.0))
	));

	evaluateAndCheckResult(inputExpr, ShPtr<Constant>());
}

//
// Tests for expressions that can be evaluated.
//

TEST_F(StrictArithmExprEvaluatorTests,
OnlyConstIntTest) {
	SCOPED_TRACE("2   ->   2");
	ShPtr<ConstInt> inputExpr(ConstInt::create(2, 64));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
NotOpExprConstIntFalseTest) {
	SCOPED_TRACE("!2   ->   false");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstInt::create(2, 64)));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
NotOpExprConstIntTrueTest) {
	SCOPED_TRACE("!0   ->   true");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstInt::create(0, 64)));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
NotOpExprConstFloatTrueTest) {
	SCOPED_TRACE("!0.0   ->   true");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstFloat::create(llvm::APFloat(0.0))));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
NotOpExprConstFloatFalseTest) {
	SCOPED_TRACE("!0.1   ->   false");
	ShPtr<NotOpExpr> inputExpr(NotOpExpr::create(
		ConstFloat::create(llvm::APFloat(0.1))));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
NegOpExprTest) {
	SCOPED_TRACE("-2(negOpExpr)   ->   2");
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(
		ConstInt::create(-2, 64, true)));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64, true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
EqOpExprConstIntTest) {
	SCOPED_TRACE("2 == 3   ->   false");
	ShPtr<EqOpExpr> inputExpr(EqOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
EqOpExprConstBoolTest) {
	SCOPED_TRACE("true == true   ->   true");
	ShPtr<EqOpExpr> inputExpr(EqOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(true)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
NeqOpExprConstBoolTest) {
	SCOPED_TRACE("false != true   ->   true");
	ShPtr<NeqOpExpr> inputExpr(NeqOpExpr::create(
		ConstBool::create(false),
		ConstBool::create(true)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
GtOpExprConstIntTrueTest) {
	SCOPED_TRACE("3 > 2   ->   true");
	ShPtr<GtOpExpr> inputExpr(GtOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
GtOpExprConstIntFalseTest) {
	SCOPED_TRACE("2 > 3   ->   false");
	ShPtr<GtOpExpr> inputExpr(GtOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
LtOpExprConstIntTrueTest) {
	SCOPED_TRACE("2 < 3   ->   true");
	ShPtr<LtOpExpr> inputExpr(LtOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
LtOpExprConstIntFalseTest) {
	SCOPED_TRACE("3 < 2   ->   true");
	ShPtr<LtOpExpr> inputExpr(LtOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
LtEqOpExprConstIntNotEqualTrue) {
	SCOPED_TRACE("2 <= 3   ->   true");
	ShPtr<LtEqOpExpr> inputExpr(LtEqOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
LtEqOpExprConstIntEqualTrueTest) {
	SCOPED_TRACE("3 <= 3   ->   true");
	ShPtr<LtEqOpExpr> inputExpr(LtEqOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
GtEqOpExprConstIntNotEqualTrue) {
	SCOPED_TRACE("3 >= 2   ->   true");
	ShPtr<GtEqOpExpr> inputExpr(GtEqOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
GtEqOpExprConstIntEqualTrueTest) {
	SCOPED_TRACE("3 >= 3   ->   true");
	ShPtr<GtEqOpExpr> inputExpr(GtEqOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleAddTest) {
	SCOPED_TRACE("2 + 2   ->   4");
	ShPtr<AddOpExpr> inputExpr(AddOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(4, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
SimpleMulTest) {
	SCOPED_TRACE("3 * 2   ->   6");
	ShPtr<MulOpExpr> inputExpr(MulOpExpr::create(
		ConstInt::create(3, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(6, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleModTest) {
	SCOPED_TRACE("6 % 2   ->   0");
	ShPtr<ModOpExpr> inputExpr(ModOpExpr::create(
		ConstInt::create(6, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(0, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleDivTest) {
	SCOPED_TRACE("6 / 3   ->   2");
	ShPtr<DivOpExpr> inputExpr(DivOpExpr::create(
		ConstInt::create(6, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(3, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleAndTrueTest) {
	SCOPED_TRACE("true && true   ->   true");
	ShPtr<AndOpExpr> inputExpr(AndOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(true)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleAndFalseTest) {
	SCOPED_TRACE("1 && 0   ->   false");
	ShPtr<AndOpExpr> inputExpr(AndOpExpr::create(
		ConstInt::create(1, 64),
		ConstInt::create(0, 64)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleOrTrueTest) {
	SCOPED_TRACE("true || false   ->   true");
	ShPtr<OrOpExpr> inputExpr(OrOpExpr::create(
		ConstBool::create(true),
		ConstBool::create(false)
	));
	ShPtr<ConstBool> refResult(ConstBool::create(true));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleOrFalseTest) {
	SCOPED_TRACE("0 && 0   ->   false");
	ShPtr<AndOpExpr> inputExpr(AndOpExpr::create(
		ConstFloat::create(llvm::APFloat(0.0)),
		ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ConstBool> refResult(ConstBool::create(false));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleBitAndTest) {
	SCOPED_TRACE("2 & 3   ->   2");
	ShPtr<BitAndOpExpr> inputExpr(BitAndOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(2, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleBitOrTest) {
	SCOPED_TRACE("2 | 3   ->   3");
	ShPtr<BitOrOpExpr> inputExpr(BitOrOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(3, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleBitXorTest) {
	SCOPED_TRACE("2 ^ 3   ->   1");
	ShPtr<BitXorOpExpr> inputExpr(BitXorOpExpr::create(
		ConstInt::create(2, 64),
		ConstInt::create(3, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(1, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
SimpleBitShlTest) {
	SCOPED_TRACE("4 << 2   ->   16");
	ShPtr<BitShlOpExpr> inputExpr(BitShlOpExpr::create(
		ConstInt::create(4, 64),
		ConstInt::create(2, 64)
	));
	ShPtr<ConstInt> refResult(ConstInt::create(16, 64));

	evaluateAndCheckResult(inputExpr, refResult);
}

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
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

TEST_F(StrictArithmExprEvaluatorTests,
NegOpExprWithVarTest) {
	SCOPED_TRACE("a(negOpExpr)(2)   ->   -2");
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	VarConstMap varConstMap;
	varConstMap[varA] = ConstInt::create(2, 64);
	ShPtr<NegOpExpr> inputExpr(NegOpExpr::create(varA));
	ShPtr<ConstInt> refResult(ConstInt::create(-2, 64, true));

	evaluateAndCheckResult(inputExpr, refResult, varConstMap);
}

TEST_F(StrictArithmExprEvaluatorTests,
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

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
