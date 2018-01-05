/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_instruction_converter_tests.cpp
* @brief Tests for instructions conversion in @c LLVMInstructionConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/tests_with_llvm_value_converter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for instructions conversion in @c LLVMInstructionConverter.
*/
class LLVMInstructionsConverterTests: public TestsWithLLVMValueConverter {
protected:
	/// @name Testing conversion of binary operators
	/// @{
	template<class T>
	void binaryOperatorIsConvertedCorrectly(llvm::Type *opType,
		llvm::Instruction::BinaryOps oper);
	template<class T>
	void binaryOperatorIsConvertedCorrectly(llvm::Type *opType,
		llvm::Instruction::BinaryOps oper, typename T::Variant variant);
	/// @}

	/// @name Testing conversion of cast instructions
	/// @{
	template<class T>
	void castInstIsConvertedCorrectly(llvm::Type *srcType, llvm::Type *dstType,
		llvm::Instruction::CastOps oper);
	template<class T>
	void castInstIsConvertedCorrectly(llvm::Type *srcType, llvm::Type *dstType,
		llvm::Instruction::CastOps oper, typename T::Variant variant);
	/// @}

	/// @name Testing conversion of compare instructions
	/// @{
	ShPtr<Expression> createICmpInstAndConvertToBir(llvm::ICmpInst::Predicate pred);
	template<class T>
	void iCmpIsConvertedCorrectly(llvm::ICmpInst::Predicate pred);
	template<class T>
	void unsignedICmpIsConvertedCorrectly(llvm::ICmpInst::Predicate pred);
	template<class T>
	void signedICmpIsConvertedCorrectly(llvm::ICmpInst::Predicate pred);
	/// @}
};

/**
* @brief Create a test scenario for binary operator.
*
* @param[in] opType Type of both operand in binary operation.
* @param[in] oper Binary operator in LLVM.
*
* @tparam T Class that represents a binary operator in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::binaryOperatorIsConvertedCorrectly(llvm::Type *opType,
		llvm::Instruction::BinaryOps oper) {
	auto op1 = std::make_unique<llvm::Argument>(opType, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(opType, "arg2");
	auto llvmInst = UPtr<llvm::BinaryOperator>(llvm::BinaryOperator::Create(
		oper, op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birExpr = cast<T>(birInst);
	ASSERT_TRUE(birExpr);
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birExpr));
}

/**
* @brief Create a test scenario for binary operator.
*
* @param[in] opType Type of both operand in binary operation.
* @param[in] oper Binary operator in LLVM.
* @param[in] variant Variant of binary operator in LLVM.
*
* @tparam T Class that represents a binary operator in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::binaryOperatorIsConvertedCorrectly(llvm::Type *opType,
		llvm::Instruction::BinaryOps oper, typename T::Variant variant) {
	auto op1 = std::make_unique<llvm::Argument>(opType, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(opType, "arg2");
	auto llvmInst = UPtr<llvm::BinaryOperator>(llvm::BinaryOperator::Create(
		oper, op1.get(), op2.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birExpr = cast<T>(birInst);
	ASSERT_TRUE(birExpr);
	ASSERT_EQ(variant, birExpr->getVariant());
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birExpr));
}

/**
* @brief Create a test scenario for cast operator.
*
* @param[in] srcType Source type of cast operation.
* @param[in] dstType Destination type of cast operation.
* @param[in] oper Cast operator in LLVM.
*
* @tparam T Class that represents a cast expression in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::castInstIsConvertedCorrectly(llvm::Type *srcType,
		llvm::Type *dstType, llvm::Instruction::CastOps oper) {
	auto op = std::make_unique<llvm::Argument>(srcType, "arg");
	auto llvmInst = UPtr<llvm::CastInst>(llvm::CastInst::Create(oper,
		op.get(), dstType));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	ASSERT_TRUE(isa<T>(birInst));
}

/**
* @brief Create a test scenario for cast operator.
*
* @param[in] srcType Source type of cast operation.
* @param[in] dstType Destination type of cast operation.
* @param[in] oper Cast operator in LLVM.
* @param[in] variant Variant of cast operator in LLVM.
*
* @tparam T Class that represents a cast expression in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::castInstIsConvertedCorrectly(llvm::Type *srcType,
		llvm::Type *dstType, llvm::Instruction::CastOps oper,
		typename T::Variant variant) {
	auto op = std::make_unique<llvm::Argument>(srcType, "arg");
	auto llvmInst = UPtr<llvm::CastInst>(llvm::CastInst::Create(oper,
		op.get(), dstType));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birCastExpr = cast<T>(birInst);
	ASSERT_TRUE(birCastExpr);
	ASSERT_EQ(variant, birCastExpr->getVariant());
}

/**
* @brief Create LLVM icmp instruction and convert it to BIR.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*/
ShPtr<Expression> LLVMInstructionsConverterTests::createICmpInstAndConvertToBir(
		llvm::ICmpInst::Predicate pred) {
	auto type = llvm::Type::getInt32Ty(context);
	auto op1 = std::make_unique<llvm::Argument>(type, "arg1");
	auto op2 = std::make_unique<llvm::Argument>(type, "arg2");
	auto llvmInst = UPtr<llvm::CmpInst>(llvm::CmpInst::Create(
		llvm::Instruction::ICmp, pred, op1.get(), op2.get()));

	return converter->convertInstructionToExpression(llvmInst.get());
}

/**
* @brief Create a test scenario for integer comparison operator.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::iCmpIsConvertedCorrectly(
		llvm::ICmpInst::Predicate pred) {
	auto birInst = createICmpInstAndConvertToBir(pred);

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birCmpExpr));
}

/**
* @brief Create a test scenario for unsigned integer comparison operator.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::unsignedICmpIsConvertedCorrectly(
		llvm::ICmpInst::Predicate pred) {
	auto birInst = createICmpInstAndConvertToBir(pred);

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
	ASSERT_EQ(T::Variant::UCmp, birCmpExpr->getVariant());
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birCmpExpr));
}

/**
* @brief Create a test scenario for signed integer comparison operator.
*
* @param[in] pred Predicate which is used for creating LLVM icmp instruction.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
void LLVMInstructionsConverterTests::signedICmpIsConvertedCorrectly(
		llvm::ICmpInst::Predicate pred) {
	auto birInst = createICmpInstAndConvertToBir(pred);

	auto birCmpExpr = cast<T>(birInst);
	ASSERT_TRUE(birCmpExpr);
	ASSERT_EQ(T::Variant::SCmp, birCmpExpr->getVariant());
	ASSERT_TRUE(areBinaryOperandsInCorrectOrder(birCmpExpr));
}

TEST_F(LLVMInstructionsConverterTests,
AddInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("AddInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<AddOpExpr>(type, llvm::Instruction::Add);
}

TEST_F(LLVMInstructionsConverterTests,
FAddInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("FAddInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<AddOpExpr>(type, llvm::Instruction::FAdd);
}

TEST_F(LLVMInstructionsConverterTests,
SubInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("SubInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<SubOpExpr>(type, llvm::Instruction::Sub);
}

TEST_F(LLVMInstructionsConverterTests,
FSubInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("FSubInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<SubOpExpr>(type, llvm::Instruction::FSub);
}

TEST_F(LLVMInstructionsConverterTests,
MulInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("MulInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<MulOpExpr>(type, llvm::Instruction::Mul);
}

TEST_F(LLVMInstructionsConverterTests,
FMulInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("FMulInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<MulOpExpr>(type, llvm::Instruction::FMul);
}

TEST_F(LLVMInstructionsConverterTests,
UDivInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("UDivInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<DivOpExpr>(type, llvm::Instruction::UDiv,
		DivOpExpr::Variant::UDiv);
}

TEST_F(LLVMInstructionsConverterTests,
SDivInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("SDivInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<DivOpExpr>(type, llvm::Instruction::SDiv,
		DivOpExpr::Variant::SDiv);
}

TEST_F(LLVMInstructionsConverterTests,
FDivInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("FDivInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<DivOpExpr>(type, llvm::Instruction::FDiv,
		DivOpExpr::Variant::FDiv);
}

TEST_F(LLVMInstructionsConverterTests,
URemInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("URemInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<ModOpExpr>(type, llvm::Instruction::URem,
		ModOpExpr::Variant::UMod);
}

TEST_F(LLVMInstructionsConverterTests,
SRemInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("SRemInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<ModOpExpr>(type, llvm::Instruction::SRem,
		ModOpExpr::Variant::SMod);
}

TEST_F(LLVMInstructionsConverterTests,
FRemInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("FRemInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<ModOpExpr>(type, llvm::Instruction::FRem,
		ModOpExpr::Variant::FMod);
}

TEST_F(LLVMInstructionsConverterTests,
ShlInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("ShlInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<BitShlOpExpr>(type, llvm::Instruction::Shl);
}

TEST_F(LLVMInstructionsConverterTests,
LShrInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("LShrInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<BitShrOpExpr>(type, llvm::Instruction::LShr,
		BitShrOpExpr::Variant::Logical);
}

TEST_F(LLVMInstructionsConverterTests,
AShrInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("AShrInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<BitShrOpExpr>(type, llvm::Instruction::AShr,
		BitShrOpExpr::Variant::Arithmetical);
}

TEST_F(LLVMInstructionsConverterTests,
AndInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("AndInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<BitAndOpExpr>(type, llvm::Instruction::And);
}

TEST_F(LLVMInstructionsConverterTests,
OrInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("OrInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<BitOrOpExpr>(type, llvm::Instruction::Or);
}

TEST_F(LLVMInstructionsConverterTests,
XorInstructionIsConvertedCorrectly) {
	auto type = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("XorInstructionIsConvertedCorrectly");
	binaryOperatorIsConvertedCorrectly<BitXorOpExpr>(type, llvm::Instruction::Xor);
}

TEST_F(LLVMInstructionsConverterTests,
BitCastInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt32PtrTy(context);
	auto dstType = llvm::Type::getInt16PtrTy(context);
	SCOPED_TRACE("BitCastInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<BitCastExpr>(srcType, dstType,
		llvm::Instruction::BitCast);
}

TEST_F(LLVMInstructionsConverterTests,
FPExtInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getFloatTy(context);
	auto dstType = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("FPExtInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<ExtCastExpr>(srcType, dstType,
		llvm::Instruction::FPExt, ExtCastExpr::Variant::FPExt);
}

TEST_F(LLVMInstructionsConverterTests,
SExtInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt16Ty(context);
	auto dstType = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("SExtInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<ExtCastExpr>(srcType, dstType,
		llvm::Instruction::SExt, ExtCastExpr::Variant::SExt);
}

TEST_F(LLVMInstructionsConverterTests,
ZExtInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt16Ty(context);
	auto dstType = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("ZExtInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<ExtCastExpr>(srcType, dstType,
		llvm::Instruction::ZExt, ExtCastExpr::Variant::ZExt);
}

TEST_F(LLVMInstructionsConverterTests,
FPToSIInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getDoubleTy(context);
	auto dstType = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("FPToSIInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<FPToIntCastExpr>(srcType, dstType,
		llvm::Instruction::FPToSI);
}

TEST_F(LLVMInstructionsConverterTests,
FPToUIInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getDoubleTy(context);
	auto dstType = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("FPToUIInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<FPToIntCastExpr>(srcType, dstType,
		llvm::Instruction::FPToUI);
}

TEST_F(LLVMInstructionsConverterTests,
TruncInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt32Ty(context);
	auto dstType = llvm::Type::getInt16Ty(context);
	SCOPED_TRACE("TruncInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<TruncCastExpr>(srcType, dstType,
		llvm::Instruction::Trunc);
}

TEST_F(LLVMInstructionsConverterTests,
FPTruncInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getDoubleTy(context);
	auto dstType = llvm::Type::getFloatTy(context);
	SCOPED_TRACE("FPTruncInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<TruncCastExpr>(srcType, dstType,
		llvm::Instruction::FPTrunc);
}

TEST_F(LLVMInstructionsConverterTests,
IntToPtrInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt32Ty(context);
	auto dstType = llvm::Type::getInt32PtrTy(context);
	SCOPED_TRACE("IntToPtrInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<IntToPtrCastExpr>(srcType, dstType,
		llvm::Instruction::IntToPtr);
}

TEST_F(LLVMInstructionsConverterTests,
PtrToIntInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt32PtrTy(context);
	auto dstType = llvm::Type::getInt32Ty(context);
	SCOPED_TRACE("PtrToIntInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<PtrToIntCastExpr>(srcType, dstType,
		llvm::Instruction::PtrToInt);
}

TEST_F(LLVMInstructionsConverterTests,
SIToFPInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt32Ty(context);
	auto dstType = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("SIToFPInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<IntToFPCastExpr>(srcType, dstType,
		llvm::Instruction::SIToFP, IntToFPCastExpr::Variant::SIToFP);
}

TEST_F(LLVMInstructionsConverterTests,
UIToFPInstructionIsConvertedCorrectly) {
	auto srcType = llvm::Type::getInt32Ty(context);
	auto dstType = llvm::Type::getDoubleTy(context);
	SCOPED_TRACE("UIToFPInstructionIsConvertedCorrectly");
	castInstIsConvertedCorrectly<IntToFPCastExpr>(srcType, dstType,
		llvm::Instruction::UIToFP, IntToFPCastExpr::Variant::UIToFP);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpEQInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpEQInstructionIsConvertedCorrectly");
	iCmpIsConvertedCorrectly<EqOpExpr>(llvm::ICmpInst::ICMP_EQ);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpNEInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpNEInstructionIsConvertedCorrectly");
	iCmpIsConvertedCorrectly<NeqOpExpr>(llvm::ICmpInst::ICMP_NE);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpUGTInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpUGTInstructionIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<GtOpExpr>(llvm::ICmpInst::ICMP_UGT);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpUGEInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpUGEInstructionIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<GtEqOpExpr>(llvm::ICmpInst::ICMP_UGE);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpULTInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpULTInstructionIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<LtOpExpr>(llvm::ICmpInst::ICMP_ULT);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpULEInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpULEInstructionIsConvertedCorrectly");
	unsignedICmpIsConvertedCorrectly<LtEqOpExpr>(llvm::ICmpInst::ICMP_ULE);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpSGTInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpSGTInstructionIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<GtOpExpr>(llvm::ICmpInst::ICMP_SGT);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpSGEInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpSGEInstructionIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<GtEqOpExpr>(llvm::ICmpInst::ICMP_SGE);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpSLTInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpSLTInstructionIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<LtOpExpr>(llvm::ICmpInst::ICMP_SLT);
}

TEST_F(LLVMInstructionsConverterTests,
ICmpSLEInstructionIsConvertedCorrectly) {
	SCOPED_TRACE("ICmpSLEInstructionIsConvertedCorrectly");
	signedICmpIsConvertedCorrectly<LtEqOpExpr>(llvm::ICmpInst::ICMP_SLE);
}

TEST_F(LLVMInstructionsConverterTests,
SelectInstructionIsConvertedCorrectly) {
	auto boolType = llvm::Type::getInt1Ty(context);
	auto intType = llvm::Type::getInt32Ty(context);
	auto cond = std::make_unique<llvm::Argument>(boolType, "cond");
	auto trueVal = std::make_unique<llvm::Argument>(intType, "true");
	auto falseVal = std::make_unique<llvm::Argument>(intType, "false");
	auto llvmInst = UPtr<llvm::SelectInst>(llvm::SelectInst::Create(cond.get(),
		trueVal.get(),falseVal.get()));

	auto birInst = converter->convertInstructionToExpression(llvmInst.get());

	auto birTernaryOpExpr = cast<TernaryOpExpr>(birInst);
	ASSERT_TRUE(birTernaryOpExpr);
	ASSERT_TRUE(areTernaryOperandsInCorrectOrder(birTernaryOpExpr));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
