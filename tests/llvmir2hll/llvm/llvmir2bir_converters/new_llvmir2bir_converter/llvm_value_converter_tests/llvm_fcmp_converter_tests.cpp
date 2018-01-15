/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_fcmp_converter_tests.cpp
* @brief Tests for the @c llvm_fcmp_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/tests_with_llvm_value_converter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c llvm_fcmp_converter module.
*/
class LLVMFCmpConverterTests: public TestsWithLLVMValueConverter {
protected:
	AssertionResult isDetectionIfEitherOperandIsQNAN(ShPtr<Expression> expr);

	template<class T>
	void fcmpIsConvertedAsSimpleExpression(llvm::FCmpInst::Predicate pred);

	template<class T>
	void orderedFCmpIsConvertedCorrectlyWithStrictSemantics(
		llvm::FCmpInst::Predicate pred);
	template<class T>
	void unorderedFCmpIsConvertedCorrectlyWithStrictSemantics(
		llvm::FCmpInst::Predicate pred);
	template<class T>
	void orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(
		llvm::FCmpInst::Predicate pred);
	template<class T>
	void unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(
		llvm::FCmpInst::Predicate pred);
};

/**
* @brief Assertion that BIR expression @a expr is for detection that one of
*        the operands is QNAN.
*/
AssertionResult LLVMFCmpConverterTests::isDetectionIfEitherOperandIsQNAN(
		ShPtr<Expression> expr) {
	auto birOrOpExpr = cast<OrOpExpr>(expr);
	if (!birOrOpExpr) {
		return AssertionFailure() << expr
			<< " does not have pattern ((x != x) || (y != y))";
	}

	auto birOp1 = cast<NeqOpExpr>(birOrOpExpr->getFirstOperand());
	if (!birOp1 || birOp1->getFirstOperand() != birOp1->getSecondOperand()) {
		return AssertionFailure() << expr
			<< " does not have pattern ((x != x) || (y != y))";
	}

	auto birOp2 = cast<NeqOpExpr>(birOrOpExpr->getSecondOperand());
	if (!birOp2 || birOp2->getFirstOperand() != birOp2->getSecondOperand()) {
		return AssertionFailure() << expr
			<< " does not have pattern ((x != x) || (y != y))";
	}

	return AssertionSuccess() << expr << " has pattern ((x != x) || (y != y))";
}

/**
* @brief Create a test scenario for floating-point comparison operator. It tests
*        that converted expression in BIR is simple comparion operator.
*
* @param[in] pred Predicate which is used for creating LLVM fcmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMFCmpConverterTests::fcmpIsConvertedAsSimpleExpression(
		llvm::FCmpInst::Predicate pred) {
	auto type = llvm::Type::getDoubleTy(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::FCmp, pred, op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birCmpExpr));
}

/**
* @brief Create a test scenario for ordered floating-point comparison operator
*        when strict FPU semantics is used.
*
* Ordered operands means that both operands are not a QNAN.
*
* @param[in] pred Predicate which is used for creating LLVM fcmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMFCmpConverterTests::orderedFCmpIsConvertedCorrectlyWithStrictSemantics(
		llvm::FCmpInst::Predicate pred) {
	converter->setOptionStrictFPUSemantics();
	fcmpIsConvertedAsSimpleExpression<T>(pred);
}

/**
* @brief Create a test scenario for unordered floating-point comparison operator
*        when strict FPU semantics is used.
*
* Unordered operands means that either operand can be a QNAN.
*
* @param[in] pred Predicate which is used for creating LLVM fcmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMFCmpConverterTests::unorderedFCmpIsConvertedCorrectlyWithStrictSemantics(
		llvm::FCmpInst::Predicate pred) {
	converter->setOptionStrictFPUSemantics();
	auto type = llvm::Type::getDoubleTy(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::FCmp, pred, op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birOrOpExpr = cast<OrOpExpr>(birInst);
	ASSERT_TRUE(birOrOpExpr);
	auto birCmpExpr = cast<T>(birOrOpExpr->getFirstOperand());
	ASSERT_TRUE(birCmpExpr);
	ASSERT_TRUE(isDetectionIfEitherOperandIsQNAN(birOrOpExpr->getSecondOperand()));
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birCmpExpr));
}

/**
* @brief Create a test scenario for ordered floating-point comparison operator
*        when strict FPU semantics is not used.
*
* Ordered operands means that both operands are not a QNAN.
*
* @param[in] pred Predicate which is used for creating LLVM fcmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMFCmpConverterTests::orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(
		llvm::FCmpInst::Predicate pred) {
	converter->setOptionStrictFPUSemantics(false);
	fcmpIsConvertedAsSimpleExpression<T>(pred);
}

/**
* @brief Create a test scenario for unordered floating-point comparison operator
*        when strict FPU semantics is not used.
*
* Unordered operands means that either operand can be a QNAN. When strict FPU
* semantics is not used, converted expression in BIR have to be equal to
* expression for ordered comparison predicate.
*
* @param[in] pred Predicate which is used for creating LLVM fcmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMFCmpConverterTests::unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(
		llvm::FCmpInst::Predicate pred) {
	converter->setOptionStrictFPUSemantics(false);
	fcmpIsConvertedAsSimpleExpression<T>(pred);
}

//
// Tests with used strict FPU semantics.
//

TEST_F(LLVMFCmpConverterTests,
FCmpOEQInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<EqOpExpr>(
		llvm::FCmpInst::FCMP_OEQ);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOGTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtOpExpr>(
		llvm::FCmpInst::FCMP_OGT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOGEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtEqOpExpr>(
		llvm::FCmpInst::FCMP_OGE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOLTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtOpExpr>(
		llvm::FCmpInst::FCMP_OLT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOLEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtEqOpExpr>(
		llvm::FCmpInst::FCMP_OLE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpONEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<NeqOpExpr>(
		llvm::FCmpInst::FCMP_ONE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUEQInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<EqOpExpr>(
		llvm::FCmpInst::FCMP_UEQ);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUGTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtOpExpr>(
		llvm::FCmpInst::FCMP_UGT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUGEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtEqOpExpr>(
		llvm::FCmpInst::FCMP_UGE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpULTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtOpExpr>(
		llvm::FCmpInst::FCMP_ULT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpULEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtEqOpExpr>(
		llvm::FCmpInst::FCMP_ULE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUNEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<NeqOpExpr>(
		llvm::FCmpInst::FCMP_UNE);
}

//
// Tests with non-strict FPU semantics.
//

TEST_F(LLVMFCmpConverterTests,
FCmpOEQInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<EqOpExpr>(
		llvm::FCmpInst::FCMP_OEQ);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOGTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtOpExpr>(
		llvm::FCmpInst::FCMP_OGT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOGEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtEqOpExpr>(
		llvm::FCmpInst::FCMP_OGE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOLTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtOpExpr>(
		llvm::FCmpInst::FCMP_OLT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpOLEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtEqOpExpr>(
		llvm::FCmpInst::FCMP_OLE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpONEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<NeqOpExpr>(
		llvm::FCmpInst::FCMP_ONE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUEQInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<EqOpExpr>(
		llvm::FCmpInst::FCMP_UEQ);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUGTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtOpExpr>(
		llvm::FCmpInst::FCMP_UGT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUGEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtEqOpExpr>(
		llvm::FCmpInst::FCMP_UGE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpULTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtOpExpr>(
		llvm::FCmpInst::FCMP_ULT);
}

TEST_F(LLVMFCmpConverterTests,
FCmpULEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtEqOpExpr>(
		llvm::FCmpInst::FCMP_ULE);
}

TEST_F(LLVMFCmpConverterTests,
FCmpUNEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<NeqOpExpr>(
		llvm::FCmpInst::FCMP_UNE);
}

//
// Tests for special fcmp predicates (which are not affected by FPU semantics).
//

TEST_F(LLVMFCmpConverterTests,
FCmpFalseInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::FCmp, llvm::FCmpInst::Predicate::FCMP_FALSE,
		op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birConst = cast<ConstBool>(birInst);
	ASSERT_TRUE(birConst);
	ASSERT_FALSE(birConst->getValue());
}

TEST_F(LLVMFCmpConverterTests,
FCmpORDInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::FCmp, llvm::FCmpInst::Predicate::FCMP_ORD,
		op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birAndOpExpr = cast<AndOpExpr>(birInst);
	ASSERT_TRUE(birAndOpExpr);
	auto birOp1 = cast<EqOpExpr>(birAndOpExpr->getFirstOperand());
	ASSERT_TRUE(birOp1);
	ASSERT_BIR_EQ(birOp1->getFirstOperand(), birOp1->getSecondOperand());
	auto birOp2 = cast<EqOpExpr>(birAndOpExpr->getSecondOperand());
	ASSERT_TRUE(birOp2);
	ASSERT_BIR_EQ(birOp2->getFirstOperand(), birOp2->getSecondOperand());
}

TEST_F(LLVMFCmpConverterTests,
FCmpUNOInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::FCmp, llvm::FCmpInst::Predicate::FCMP_UNO,
		op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	ASSERT_TRUE(isDetectionIfEitherOperandIsQNAN(birInst));
}

TEST_F(LLVMFCmpConverterTests,
FCmpTrueInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::FCmp, llvm::FCmpInst::Predicate::FCMP_TRUE,
		op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birConst = cast<ConstBool>(birInst);
	ASSERT_TRUE(birConst);
	ASSERT_TRUE(birConst->getValue());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
