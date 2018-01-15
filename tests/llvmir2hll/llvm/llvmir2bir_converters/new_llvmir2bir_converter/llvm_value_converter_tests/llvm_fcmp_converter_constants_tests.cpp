/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_fcmp_converter_constants_tests.cpp
* @brief Tests for the @c llvm_fcmp_converter module (for converting of the
*        constant expressions).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/assertions.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c llvm_fcmp_converter module (for converting of the
*        constant expressions).
*/
class LLVMFCmpConverterConstantsTests: public NewLLVMIR2BIRConverterBaseTests {
protected:
	AssertionResult isDetectionIfEitherOperandIsQNAN(ShPtr<Expression> expr);

	template<class T>
	void fcmpIsConvertedAsSimpleExpression(const std::string &pred);

	template<class T>
	void orderedFCmpIsConvertedCorrectlyWithStrictSemantics(const std::string &pred);
	template<class T>
	void unorderedFCmpIsConvertedCorrectlyWithStrictSemantics(const std::string &pred);
	template<class T>
	void orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(const std::string &pred);
	template<class T>
	void unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(const std::string &pred);
};

/**
* @brief Assertion that BIR expression @a expr is for detection that one of
*        the operands is QNAN.
*/
AssertionResult LLVMFCmpConverterConstantsTests::isDetectionIfEitherOperandIsQNAN(
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
void LLVMFCmpConverterConstantsTests::fcmpIsConvertedAsSimpleExpression(
		const std::string &pred) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 fcmp )" + pred + R"( (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 1.0)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto birCmpExpr = cast<T>(retStmt->getRetVal());
	ASSERT_TRUE(birCmpExpr);
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
void LLVMFCmpConverterConstantsTests::orderedFCmpIsConvertedCorrectlyWithStrictSemantics(
		const std::string &pred) {
	optionStrictFPUSemantics = true;
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
void LLVMFCmpConverterConstantsTests::unorderedFCmpIsConvertedCorrectlyWithStrictSemantics(
		const std::string &pred) {
	optionStrictFPUSemantics = true;
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 fcmp )" + pred + R"( (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 1.0)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto birOrOpExpr = cast<OrOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(birOrOpExpr);
	auto birCmpExpr = cast<T>(birOrOpExpr->getFirstOperand());
	ASSERT_TRUE(birCmpExpr);
	ASSERT_TRUE(isDetectionIfEitherOperandIsQNAN(birOrOpExpr->getSecondOperand()));
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
void LLVMFCmpConverterConstantsTests::orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(
		const std::string &pred) {
	optionStrictFPUSemantics = false;
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
void LLVMFCmpConverterConstantsTests::unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics(
		const std::string &pred) {
	optionStrictFPUSemantics = false;
	fcmpIsConvertedAsSimpleExpression<T>(pred);
}

//
// Tests with used strict FPU semantics.
//

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOEQInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<EqOpExpr>("oeq");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOGTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtOpExpr>("ogt");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOGEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtEqOpExpr>("oge");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOLTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtOpExpr>("olt");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOLEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtEqOpExpr>("ole");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpONEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithStrictSemantics<NeqOpExpr>("one");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUEQInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<EqOpExpr>("ueq");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUGTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtOpExpr>("ugt");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUGEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<GtEqOpExpr>("uge");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpULTInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtOpExpr>("ult");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpULEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<LtEqOpExpr>("ule");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUNEInstructionIsConvertedCorrectlyWithStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithStrictSemantics<NeqOpExpr>("une");
}

//
// Tests with non-strict FPU semantics.
//

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOEQInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<EqOpExpr>("oeq");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOGTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtOpExpr>("ogt");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOGEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtEqOpExpr>("oge");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOLTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtOpExpr>("olt");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpOLEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtEqOpExpr>("ole");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpONEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	orderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<NeqOpExpr>("one");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUEQInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<EqOpExpr>("ueq");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUGTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtOpExpr>("ugt");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUGEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<GtEqOpExpr>("uge");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpULTInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtOpExpr>("ult");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpULEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<LtEqOpExpr>("ule");
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUNEInstructionIsConvertedCorrectlyWithNonStrictSemantics) {
	unorderedFCmpIsConvertedCorrectlyWithNonStrictSemantics<NeqOpExpr>("une");
}

//
// Tests for special fcmp predicates (which are not affected by FPU semantics).
//

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpFalseInstructionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 fcmp false (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 1.0)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto birConst = cast<ConstBool>(retStmt->getRetVal());
	ASSERT_TRUE(birConst);
	ASSERT_FALSE(birConst->getValue());
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpORDInstructionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 fcmp ord (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 1.0)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto birAndOpExpr = cast<AndOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(birAndOpExpr);
	auto birOp1 = cast<EqOpExpr>(birAndOpExpr->getFirstOperand());
	ASSERT_TRUE(birOp1);
	ASSERT_BIR_EQ(birOp1->getFirstOperand(), birOp1->getSecondOperand());
	auto birOp2 = cast<EqOpExpr>(birAndOpExpr->getSecondOperand());
	ASSERT_TRUE(birOp2);
	ASSERT_BIR_EQ(birOp2->getFirstOperand(), birOp2->getSecondOperand());
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpUNOInstructionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 fcmp uno (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 1.0)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = retStmt->getRetVal();
	ASSERT_TRUE(isDetectionIfEitherOperandIsQNAN(retVal));
}

TEST_F(LLVMFCmpConverterConstantsTests,
FCmpTrueInstructionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 fcmp true (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 1.0)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto birConst = cast<ConstBool>(retStmt->getRetVal());
	ASSERT_TRUE(birConst);
	ASSERT_TRUE(birConst->getValue());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
