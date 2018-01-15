/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_instruction_converter_constants_tests.cpp
* @brief Tests for constant expressions conversion in @c LLVMInstructionConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for constant expressions conversion in @c LLVMInstructionConverter.
*/
class LLVMInstructionConverterConstExpressionsTests: public NewLLVMIR2BIRConverterBaseTests {
protected:
	/// @name Testing conversion of integral compare constant expressions
	/// @{
	ShPtr<Expression> createICmpInstAndConvertToBir(const std::string &pred);
	template<class T>
	void iCmpIsConvertedCorrectly(const std::string &pred);
	template<class T>
	void unsignedICmpIsConvertedCorrectly(const std::string &pred);
	template<class T>
	void signedICmpIsConvertedCorrectly(const std::string &pred);
	/// @}
};

/**
* @brief Create LLVM integral compare constant expression and convert it to BIR.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*/
ShPtr<Expression> LLVMInstructionConverterConstExpressionsTests::createICmpInstAndConvertToBir(
		const std::string &pred) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i1 @function() {
			ret i1 icmp )" + pred + R"( (i32 ptrtoint (i32* @g to i32), i32 1)
		}
	)");

	auto f = module->getFuncByName("function");
	auto retStmt = cast<ReturnStmt>(f->getBody());
	return retStmt->getRetVal();
}

/**
* @brief Create a test scenario for integer comparison operator.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMInstructionConverterConstExpressionsTests::iCmpIsConvertedCorrectly(
		const std::string &pred) {
	auto birInst = createICmpInstAndConvertToBir(pred);

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
}

/**
* @brief Create a test scenario for unsigned integer comparison operator.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMInstructionConverterConstExpressionsTests::unsignedICmpIsConvertedCorrectly(
		const std::string &pred) {
	auto birInst = createICmpInstAndConvertToBir(pred);

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
	ASSERT_EQ(T::Variant::UCmp, birCmpExpr->getVariant());
}

/**
* @brief Create a test scenario for signed integer comparison operator.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMInstructionConverterConstExpressionsTests::signedICmpIsConvertedCorrectly(
		const std::string &pred) {
	auto birInst = createICmpInstAndConvertToBir(pred);

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
	ASSERT_EQ(T::Variant::SCmp, birCmpExpr->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantGetElementPtrWhichGetsStringConstantIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = private constant [12 x i8] c"hello world\00"

		define void @function() {
			call i32 @puts(i8* getelementptr inbounds ([12 x i8], [12 x i8]* @g, i32 0, i32 0))
			ret void
		}

		declare i32 @puts(i8*)
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	auto callExpr = cast<CallExpr>(callStmt->getCall());
	ASSERT_TRUE(callExpr);
	auto callArg = cast<ConstString>(callExpr->getArg(1));
	ASSERT_TRUE(callArg);
	ASSERT_EQ("hello world"s, callArg->getValueAsEscapedCString());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantGetElementPtrWhichGetsWideStringConstantIsConvertedCorrectly) {
	EXPECT_CALL(*configMock, isGlobalVarStoringWideString("g"))
		.WillRepeatedly(Return(true));

	auto module = convertLLVMIR2BIR(R"(
		@g = constant [6 x i16] [i16 225, i16 269, i16 345, i16 353, i16 382, i16 0]

		define void @function() {
			call i32 (i16*, ...) @wprintf(i16* getelementptr inbounds ([6 x i16], [6 x i16]* @g, i32 0, i32 0))
			ret void
		}

		declare i32 @wprintf(i16*, ...)
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	auto callExpr = cast<CallExpr>(callStmt->getCall());
	ASSERT_TRUE(callExpr);
	auto callArg = cast<ConstString>(callExpr->getArg(1));
	ASSERT_TRUE(callArg);
	ASSERT_TRUE(callArg->isWideString());
	ASSERT_EQ("\\x00e1\\x010d\\x0159\\x0161\\x017e"s, callArg->getValueAsEscapedCString());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
StringArrayIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@str1 = constant [4 x i8] c"abc\00"
		@str2 = constant [3 x i8] c"xy\00"

		@g = constant [2 x i8*] [
			i8* getelementptr inbounds ([4 x i8], [4 x i8]* @str1, i32 0, i32 0),
			i8* getelementptr inbounds ([3 x i8], [3 x i8]* @str2, i32 0, i32 0)
		]
	)");

	auto globVar = module->getGlobalVarByName("g");
	ASSERT_TRUE(globVar);
	auto globVarInit = cast<Constant>(module->getInitForGlobalVar(globVar));
	ASSERT_TRUE(globVarInit);
	ASSERT_EQ("[\"abc\", \"xy\"]"s, globVarInit->getTextRepr());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantGetElementPtrWithNonZeroFirstIndexIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		%s = type { i32, i32 }

		@g = external constant [6 x %s]

		declare void @test(i32*)

		define void @function() {
			call void @test(i32* getelementptr ([6 x %s], [6 x %s]* @g, i32 1, i32 4, i32 1))
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt = cast<CallStmt>(f->getBody());
	ASSERT_TRUE(callStmt);
	auto callExpr = cast<CallExpr>(callStmt->getCall());
	ASSERT_TRUE(callExpr);
	auto addrOp1 = cast<AddressOpExpr>(callExpr->getArg(1));
	ASSERT_TRUE(addrOp1);
	auto structOp1 = cast<StructIndexOpExpr>(addrOp1->getOperand());
	ASSERT_TRUE(structOp1);
	auto arrOp1 = cast<ArrayIndexOpExpr>(structOp1->getFirstOperand());
	ASSERT_TRUE(arrOp1);
	auto arrOp2 = cast<ArrayIndexOpExpr>(arrOp1->getFirstOperand());
	ASSERT_TRUE(arrOp2);
	ASSERT_TRUE(isConstInt(arrOp2->getSecondOperand(), 1));
	ASSERT_TRUE(isConstInt(arrOp1->getSecondOperand(), 4));
	ASSERT_TRUE(isConstInt(structOp1->getSecondOperand(), 1));
	auto addrOp2 = cast<AddressOpExpr>(arrOp2->getFirstOperand());
	ASSERT_TRUE(addrOp2);
	ASSERT_BIR_EQ(module->getGlobalVarByName("g"), addrOp2->getOperand());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantPtrToIntWithStringIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = private constant [12 x i8] c"hello world\00"

		define i32 @function(i32 %val) {
			ret i32 ptrtoint ([12 x i8]* @g to i32)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto ptrToInt = cast<PtrToIntCastExpr>(retStmt->getRetVal());
	ASSERT_TRUE(ptrToInt);
	auto str = cast<ConstString>(ptrToInt->getOperand());
	ASSERT_TRUE(str);
	ASSERT_EQ("hello world"s, str->getValueAsEscapedCString());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantAddIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 add (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<AddOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFAddIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double fadd (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 2.5)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<AddOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantSubIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 sub (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<SubOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFSubIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double fsub (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 2.5)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<SubOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantMulIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 mul (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<MulOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFMulIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double fmul (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 2.5)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<MulOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantUDivIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 udiv (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<DivOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(DivOpExpr::Variant::UDiv, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantSDivIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 sdiv (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<DivOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(DivOpExpr::Variant::SDiv, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFDivIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double fdiv (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 2.5)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<DivOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(DivOpExpr::Variant::FDiv, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantURemIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 urem (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<ModOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(ModOpExpr::Variant::UMod, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantSRemIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 srem (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<ModOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(ModOpExpr::Variant::SMod, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFRemIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double frem (double sitofp (i32 ptrtoint (i32* @g to i32) to double), double 2.5)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<ModOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(ModOpExpr::Variant::FMod, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantShlIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 shl (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<BitShlOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantLShrIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 lshr (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<BitShrOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(BitShrOpExpr::Variant::Logical, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantAShrIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 ashr (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<BitShrOpExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(BitShrOpExpr::Variant::Arithmetical, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantAndIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 and (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<BitAndOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantOrIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 or (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<BitOrOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantXorIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 xor (i32 ptrtoint (i32* @g to i32), i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<BitXorOpExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantBitCastIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = constant [2 x i16] [i16 40, i16 0]

		define i32* @function() {
			ret i32* bitcast ([2 x i16]* @g to i32*)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<BitCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFPExtIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define fp128 @function() {
			ret fp128 fpext (double sitofp (i32 ptrtoint (i32* @g to i32) to double) to fp128)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<ExtCastExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(ExtCastExpr::Variant::FPExt, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantSExtIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i64 @function() {
			ret i64 sext (i32 ptrtoint (i32* @g to i32) to i64)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<ExtCastExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(ExtCastExpr::Variant::SExt, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantZExtIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i64 @function() {
			ret i64 zext (i32 ptrtoint (i32* @g to i32) to i64)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<ExtCastExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(ExtCastExpr::Variant::ZExt, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFPToSIIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 fptosi (double sitofp (i32 ptrtoint (i32* @g to i32) to double) to i32)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<FPToIntCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFPToUIIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 fptoui (double sitofp (i32 ptrtoint (i32* @g to i32) to double) to i32)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<FPToIntCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantTruncIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i16 @function() {
			ret i16 trunc (i32 add (i32 ptrtoint (i32* @g to i32), i32 2) to i16)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<TruncCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantFPTruncIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define float @function() {
			ret float fptrunc (double sitofp (i32 ptrtoint (i32* @g to i32) to double) to float)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<TruncCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantIntToPtrIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32* @function() {
			ret i32* inttoptr (i32 1 to i32*)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<IntToPtrCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantPtrToIntIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = constant [2 x i16] [i16 40, i16 0]

		define i32 @function() {
			ret i32 ptrtoint ([2 x i16]* @g to i32)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<PtrToIntCastExpr>(retStmt->getRetVal()));
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantSIToFPIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double sitofp (i32 ptrtoint (i32* @g to i32) to double)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<IntToFPCastExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(IntToFPCastExpr::Variant::SIToFP, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantUIToFPIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define double @function() {
			ret double uitofp (i32 ptrtoint (i32* @g to i32) to double)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	auto retVal = cast<IntToFPCastExpr>(retStmt->getRetVal());
	ASSERT_TRUE(retVal);
	ASSERT_EQ(IntToFPCastExpr::Variant::UIToFP, retVal->getVariant());
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpEQIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpEQIsConvertedCorrectly");
	iCmpIsConvertedCorrectly<EqOpExpr>("eq");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpNEIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpNEIsConvertedCorrectly");
	iCmpIsConvertedCorrectly<NeqOpExpr>("ne");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpUGTIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpUGTIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<GtOpExpr>("ugt");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpUGEIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpUGEIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<GtEqOpExpr>("uge");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpULTIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpULTIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<LtOpExpr>("ult");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpULEIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpULEIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<LtEqOpExpr>("ule");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpSGTIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpSGTIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<GtOpExpr>("sgt");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpSGEIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpSGEIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<GtEqOpExpr>("sge");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpSLTIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpSLTIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<LtOpExpr>("slt");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantICmpSLEIsConvertedCorrectly) {
	SCOPED_TRACE("ConstantICmpSLEIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<LtEqOpExpr>("sle");
}

TEST_F(LLVMInstructionConverterConstExpressionsTests,
ConstantSelectIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1

		define i32 @function() {
			ret i32 select (i1 icmp eq (i32 ptrtoint (i32* @g to i32), i32 1), i32 1, i32 2)
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto retStmt = cast<ReturnStmt>(f->getBody());
	ASSERT_TRUE(retStmt);
	ASSERT_TRUE(isa<TernaryOpExpr>(retStmt->getRetVal()));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
