/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_instruction_converter.cpp
* @brief Implementation of LLVMInstructionConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/User.h>
#include <llvm/IR/Value.h>

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
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
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
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_fcmp_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_instruction_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/string_conversions.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/// Size of integral value storing index of composite type element in bits.
/// It was chosen to use 32 bits because it is enough to store index
/// for huge structures.
const unsigned COMPOSITE_TYPE_INDEX_SIZE_BITS = 32;

} // anonymous namespace

/**
* @brief Constructs a new converter.
*/
LLVMInstructionConverter::LLVMInstructionConverter():
	fcmpConverter(std::make_unique<LLVMFCmpConverter>()) {}

/**
* @brief Destructs the converter.
*/
LLVMInstructionConverter::~LLVMInstructionConverter() {}

/**
* @brief Converts the given LLVM constant expression @a cExpr into an expression
*        in BIR.
*
* @par Preconditions
*  - @a cExpr is non-null
*/
ShPtr<Expression> LLVMInstructionConverter::convertConstExprToExpression(
		llvm::ConstantExpr *cExpr) {
	PRECONDITION_NON_NULL(cExpr);

	auto opCode = cExpr->getOpcode();
	if (llvm::Instruction::isBinaryOp(opCode)) {
		return convertBinaryOpToExpression(*cExpr, opCode);
	}

	switch (opCode) {
		case llvm::Instruction::BitCast:
			return convertCastInstToExpression<BitCastExpr>(*cExpr);

		case llvm::Instruction::FCmp:
			return convertFCmpInstToExpression(*cExpr,
				cExpr->getPredicate());

		case llvm::Instruction::FPExt:
			return convertExtCastInstToExpression(*cExpr,
				ExtCastExpr::Variant::FPExt);

		case llvm::Instruction::FPToSI:
		case llvm::Instruction::FPToUI:
			return convertFPToIntInstToExpression(*cExpr);

		case llvm::Instruction::FPTrunc:
		case llvm::Instruction::Trunc:
			return convertTruncInstToExpression(*cExpr);

		case llvm::Instruction::GetElementPtr:
			return convertGetElementPtrToExpression(*cExpr);

		case llvm::Instruction::ICmp:
			return convertICmpInstToExpression(*cExpr,
				cExpr->getPredicate());

		case llvm::Instruction::IntToPtr:
			return convertCastInstToExpression<IntToPtrCastExpr>(*cExpr);

		case llvm::Instruction::PtrToInt:
			return convertCastInstToExpression<PtrToIntCastExpr>(*cExpr);

		case llvm::Instruction::Select:
			return convertSelectInstToExpression(*cExpr);

		case llvm::Instruction::SExt:
			return convertExtCastInstToExpression(*cExpr,
				ExtCastExpr::Variant::SExt);

		case llvm::Instruction::SIToFP:
			return convertIntToFPInstToExpression(*cExpr,
				IntToFPCastExpr::Variant::SIToFP);

		case llvm::Instruction::UIToFP:
			return convertIntToFPInstToExpression(*cExpr,
				IntToFPCastExpr::Variant::UIToFP);

		case llvm::Instruction::ZExt:
			return convertExtCastInstToExpression(*cExpr,
				ExtCastExpr::Variant::ZExt);

		default:
			FAIL("unsupported constant expression: " <<
				const_cast<llvm::ConstantExpr &>(*cExpr));
			break;
	}

	return nullptr;
}

/**
* @brief Converts the given LLVM instruction @a inst into an expression in BIR.
*
* @par Preconditions
*  - @a inst is non-null
*/
ShPtr<Expression> LLVMInstructionConverter::convertInstructionToExpression(
		llvm::Instruction *inst) {
	PRECONDITION_NON_NULL(inst);

	return visit(*inst);
}

/**
* @brief Converts the given LLVM call instruction @a inst into an expression in BIR.
*/
ShPtr<CallExpr> LLVMInstructionConverter::convertCallInstToCallExpr(llvm::CallInst &inst) {
	ExprVector args;
	for (auto &arg: inst.arg_operands()) {
		args.push_back(getConverter()->convertValueToExpression(arg));
	}

	auto calledExpr = getConverter()->convertValueToExpression(inst.getCalledValue());
	return CallExpr::create(calledExpr, args);
}

/**
* @brief Generates access to aggregate type as a part of conversion of LLVM
*        instruction insertvalue or extractvalue.
*
* @param[in] type Type of aggregate type.
* @param[in] base Base expression.
* @param[in] indices Array of indices.
*/
ShPtr<Expression> LLVMInstructionConverter::generateAccessToAggregateType(
		llvm::CompositeType *type, const ShPtr<Expression> &base,
		const llvm::ArrayRef<unsigned> &indices) {
	auto typeIt = type;
	auto access = base;
	for (const auto &index: indices) {
		auto indexBir = ConstInt::create(index, COMPOSITE_TYPE_INDEX_SIZE_BITS);

		if (typeIt->isStructTy()) {
			access = StructIndexOpExpr::create(access, indexBir);
		} else if (typeIt->isArrayTy()) {
			access = ArrayIndexOpExpr::create(access, indexBir);
		}

		typeIt = llvm::dyn_cast<llvm::CompositeType>(typeIt->getTypeAtIndex(index));
	}

	return access;
}

/**
* @brief Sets converter for LLVM values to the given @a conv.
*
* @par Preconditions
*  - @a conv is non-null
*/
void LLVMInstructionConverter::setLLVMValueConverter(ShPtr<LLVMValueConverter> conv) {
	PRECONDITION_NON_NULL(conv);

	converter = conv;
}

/**
* @brief Enables/disables the use of strict FPU semantics.
*
* @param[in] strict If @c true, enables the use of strict FPU semantics. If @c
*                   false, disables the use of strict FPU semantics.
*/
void LLVMInstructionConverter::setOptionStrictFPUSemantics(bool strict) {
	fcmpConverter->setOptionStrictFPUSemantics(strict);
}

/**
* @brief Converts the given LLVM binary operation @a inst into an expression in
*        BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitBinaryOperator(
		llvm::BinaryOperator &inst) {
	return convertBinaryOpToExpression(inst, inst.getOpcode());
}

/**
* @brief Converts the given LLVM bitcast instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitBitCastInst(llvm::BitCastInst &inst) {
	return convertCastInstToExpression<BitCastExpr>(inst);
}

/**
* @brief Converts the given LLVM fpext instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitFPExtInst(llvm::FPExtInst &inst) {
	return convertExtCastInstToExpression(inst, ExtCastExpr::Variant::FPExt);
}

/**
* @brief Converts the given LLVM sext instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitSExtInst(llvm::SExtInst &inst) {
	return convertExtCastInstToExpression(inst, ExtCastExpr::Variant::SExt);
}

/**
* @brief Converts the given LLVM zext instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitZExtInst(llvm::ZExtInst &inst) {
	return convertExtCastInstToExpression(inst, ExtCastExpr::Variant::ZExt);
}

/**
* @brief Converts the given LLVM fptosi instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitFPToSIInst(llvm::FPToSIInst &inst) {
	return convertFPToIntInstToExpression(inst);
}

/**
* @brief Converts the given LLVM fptoui instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitFPToUIInst(llvm::FPToUIInst &inst) {
	return convertFPToIntInstToExpression(inst);
}

/**
* @brief Converts the given LLVM trunc instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitTruncInst(llvm::TruncInst &inst) {
	return convertTruncInstToExpression(inst);
}

/**
* @brief Converts the given LLVM fptrunc instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitFPTruncInst(llvm::FPTruncInst &inst) {
	return convertTruncInstToExpression(inst);
}

/**
* @brief Converts the given LLVM inttoptr instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitIntToPtrInst(llvm::IntToPtrInst &inst) {
	return convertCastInstToExpression<IntToPtrCastExpr>(inst);
}

/**
* @brief Converts the given LLVM ptrtoint instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitPtrToIntInst(llvm::PtrToIntInst &inst) {
	return convertCastInstToExpression<PtrToIntCastExpr>(inst);
}

/**
* @brief Converts the given LLVM sitofp instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitSIToFPInst(llvm::SIToFPInst &inst) {
	return convertIntToFPInstToExpression(inst, IntToFPCastExpr::Variant::SIToFP);
}

/**
* @brief Converts the given LLVM uitofp instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitUIToFPInst(llvm::UIToFPInst &inst) {
	return convertIntToFPInstToExpression(inst, IntToFPCastExpr::Variant::UIToFP);
}

/**
* @brief Converts the given LLVM icmp instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitICmpInst(llvm::ICmpInst &inst) {
	return convertICmpInstToExpression(inst, inst.getPredicate());
}

/**
* @brief Converts the given LLVM fcmp instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitFCmpInst(llvm::FCmpInst &inst) {
	return convertFCmpInstToExpression(inst, inst.getPredicate());
}

/**
* @brief Converts the given LLVM select instruction @a inst into an expression
*        in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitSelectInst(llvm::SelectInst &inst) {
	return convertSelectInstToExpression(inst);
}

/**
* @brief Converts the given LLVM getElementPtr instruction @a inst into
*        an expression in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitGetElementPtrInst(
		llvm::GetElementPtrInst &inst) {
	return convertGetElementPtrToExpression(inst);
}

/**
* @brief Converts the given LLVM extractvalue instruction @a inst into
*        an expression in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitExtractValueInst(
		llvm::ExtractValueInst &inst) {
	auto type = llvm::cast<llvm::CompositeType>(inst.getAggregateOperand()->getType());
	auto base = getConverter()->convertValueToExpression(inst.getAggregateOperand());
	return generateAccessToAggregateType(type, base, inst.getIndices());
}

/**
* @brief Converts the given LLVM instruction @a inst into an expression in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::visitInstruction(llvm::Instruction &inst) {
	FAIL("unsupported instruction: " << inst);
	return nullptr;
}

/**
* @brief Converts the given LLVM binary operation @a inst with opcode @a opcode
*        into an expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::BinaryOperator
* because this method can handle also constant binary expressions.
*/
ShPtr<Expression> LLVMInstructionConverter::convertBinaryOpToExpression(
		llvm::User &inst, unsigned opcode) {
	auto op1 = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto op2 = getConverter()->convertValueToExpression(inst.getOperand(1));

	switch (opcode) {
		case llvm::Instruction::Add:
		case llvm::Instruction::FAdd:
			return AddOpExpr::create(op1, op2);

		case llvm::Instruction::Sub:
		case llvm::Instruction::FSub:
			return SubOpExpr::create(op1, op2);

		case llvm::Instruction::Mul:
		case llvm::Instruction::FMul:
			return MulOpExpr::create(op1, op2);

		case llvm::Instruction::UDiv:
			return DivOpExpr::create(op1, op2,
				DivOpExpr::Variant::UDiv);

		case llvm::Instruction::SDiv:
			return DivOpExpr::create(op1, op2,
				DivOpExpr::Variant::SDiv);

		case llvm::Instruction::FDiv:
			return DivOpExpr::create(op1, op2,
				DivOpExpr::Variant::FDiv);

		case llvm::Instruction::URem:
			return ModOpExpr::create(op1, op2,
				ModOpExpr::Variant::UMod);

		case llvm::Instruction::SRem:
			return ModOpExpr::create(op1, op2,
				ModOpExpr::Variant::SMod);

		case llvm::Instruction::FRem:
			return ModOpExpr::create(op1, op2,
				ModOpExpr::Variant::FMod);

		case llvm::Instruction::Shl:
			return BitShlOpExpr::create(op1, op2);

		case llvm::Instruction::LShr:
			return BitShrOpExpr::create(op1, op2,
				BitShrOpExpr::Variant::Logical);

		case llvm::Instruction::AShr:
			return BitShrOpExpr::create(op1, op2,
				BitShrOpExpr::Variant::Arithmetical);

		case llvm::Instruction::And:
			return BitAndOpExpr::create(op1, op2);

		case llvm::Instruction::Or:
			return BitOrOpExpr::create(op1, op2);

		case llvm::Instruction::Xor:
			return BitXorOpExpr::create(op1, op2);

		default:
			FAIL("unsupported binary operator: " << inst);
			return nullptr;
	}

	return nullptr;
}

/**
* @brief Converts the given LLVM icmp instruction @a inst with compare predicate
*        @a predicate into an expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::ICmpInst because
* this method can handle also constant integral compare expressions.
*/
ShPtr<Expression> LLVMInstructionConverter::convertICmpInstToExpression(
		llvm::User &inst, unsigned predicate) {
	auto op1 = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto op2 = getConverter()->convertValueToExpression(inst.getOperand(1));

	switch (predicate) {
		case llvm::CmpInst::Predicate::ICMP_EQ:
			return EqOpExpr::create(op1, op2);

		case llvm::CmpInst::Predicate::ICMP_NE:
			return NeqOpExpr::create(op1, op2);

		case llvm::CmpInst::Predicate::ICMP_UGT:
			return GtOpExpr::create(op1, op2,
				GtOpExpr::Variant::UCmp);

		case llvm::CmpInst::Predicate::ICMP_UGE:
			return GtEqOpExpr::create(op1, op2,
				GtEqOpExpr::Variant::UCmp);

		case llvm::CmpInst::Predicate::ICMP_ULT:
			return LtOpExpr::create(op1, op2,
				LtOpExpr::Variant::UCmp);

		case llvm::CmpInst::Predicate::ICMP_ULE:
			return LtEqOpExpr::create(op1, op2,
				LtEqOpExpr::Variant::UCmp);

		case llvm::CmpInst::Predicate::ICMP_SGT:
			return GtOpExpr::create(op1, op2,
				GtOpExpr::Variant::SCmp);

		case llvm::CmpInst::Predicate::ICMP_SGE:
			return GtEqOpExpr::create(op1, op2,
				GtEqOpExpr::Variant::SCmp);

		case llvm::CmpInst::Predicate::ICMP_SLT:
			return LtOpExpr::create(op1, op2,
				LtOpExpr::Variant::SCmp);

		case llvm::CmpInst::Predicate::ICMP_SLE:
			return LtEqOpExpr::create(op1, op2,
				LtEqOpExpr::Variant::SCmp);

		default:
			FAIL("unsupported icmp predicate: " << inst);
			return nullptr;
	}

	return nullptr;
}

/**
* @brief Converts the given LLVM fcmp instruction @a inst with compare predicate
*        @a predicate into an expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::FCmpInst because
* this method can handle also constant floating-point compare expressions.
*/
ShPtr<Expression> LLVMInstructionConverter::convertFCmpInstToExpression(
		llvm::User &inst, unsigned predicate) {
	auto op1 = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto op2 = getConverter()->convertValueToExpression(inst.getOperand(1));
	auto expr = fcmpConverter->convertToExpression(op1, op2, predicate);
	if (!expr) {
		FAIL("unsupported fcmp predicate: " << inst);
	}

	return expr;
}

/**
* @brief Converts the given LLVM select instruction @a inst into an expression
*        in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::SelectInst
* because this method can handle also constant select expressions.
*/
ShPtr<Expression> LLVMInstructionConverter::convertSelectInstToExpression(
		llvm::User &inst) {
	auto cond = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto trueValue = getConverter()->convertValueToExpression(inst.getOperand(1));
	auto falseValue = getConverter()->convertValueToExpression(inst.getOperand(2));
	return TernaryOpExpr::create(cond, trueValue, falseValue);
}

/**
* @brief Converts the given LLVM extension cast instruction @a inst into an
*        extension cast expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::CastInst
* because this method can handle also constant cast expressions.
*
* @param[in] inst Given LLVM extension cast instruction.
* @param[in] variant Variant of extension cast expression in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::convertExtCastInstToExpression(
		llvm::User &inst, ExtCastExpr::Variant variant) {
	auto op = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto dstType = getConverter()->convertType(inst.getType());
	return ExtCastExpr::create(op, dstType, variant);
}

/**
* @brief Converts the given LLVM int to FP cast instruction @a inst into an int
*        to FP cast expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::CastInst
* because this method can handle also constant cast expressions.
*
* @param[in] inst Given LLVM int to FP cast instruction.
* @param[in] variant Variant of int to FP cast expression in BIR.
*/
ShPtr<Expression> LLVMInstructionConverter::convertIntToFPInstToExpression(
		llvm::User &inst, IntToFPCastExpr::Variant variant) {
	auto op = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto dstType = getConverter()->convertType(inst.getType());
	return IntToFPCastExpr::create(op, dstType, variant);
}

/**
* @brief Converts the given LLVM FP to int cast instruction @a inst into a FP
*        to int cast expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::CastInst
* because this method can handle also constant cast expressions.
*/
ShPtr<Expression> LLVMInstructionConverter::convertFPToIntInstToExpression(
		llvm::User &inst) {
	return convertCastInstToExpression<FPToIntCastExpr>(inst);
}

/**
* @brief Converts the given LLVM trunc instruction @a inst into a trunc cast
*        expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::CastInst
* because this method can handle also constant cast expressions.
*/
ShPtr<Expression> LLVMInstructionConverter::convertTruncInstToExpression(
		llvm::User &inst) {
	return convertCastInstToExpression<TruncCastExpr>(inst);
}

/**
* @brief Converts the given LLVM cast instruction @a inst into a specified
*        expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::CastInst
* because this method can handle also constant cast expressions.
*
* @tparam T Class that represents a cast expression in BIR.
*/
template<class T>
ShPtr<Expression> LLVMInstructionConverter::convertCastInstToExpression(llvm::User &inst) {
	auto op = getConverter()->convertValueToExpression(inst.getOperand(0));
	auto dstType = getConverter()->convertType(inst.getType());
	return T::create(op, dstType);
}

/**
* @brief Converts the given LLVM getelementptr instruction @a inst into
*        an expression in BIR.
*
* Note that @a inst type is @c llvm::User instead of @c llvm::GetElementPtrInst
* because this method can handle also constant getelementptr expression.
*/
ShPtr<Expression> LLVMInstructionConverter::convertGetElementPtrToExpression(
		llvm::User &inst) {
	auto pointedValue = inst.getOperand(0);

	if (auto globVar = llvm::dyn_cast<llvm::GlobalVariable>(pointedValue)) {
		if (getConverter()->storesStringLiteral(*globVar)) {
			return getInitializerAsConstString(globVar);
		}
	}

	auto it = llvm::gep_type_begin(inst);
	auto e = llvm::gep_type_end(inst);
	if (it != e) {
		ShPtr<Expression> base;
		auto index = getConverter()->convertValueToExpression(it.getOperand());
		auto cInt = cast<ConstInt>(index);
		if (cInt && cInt->isZero()) {
			base = getConverter()->convertValueToExpressionDirectly(pointedValue);
			++it;
		} else {
			base = getConverter()->convertValueToExpression(pointedValue);
		}

		return convertGEPIndices(base, it, e);
	}

	FAIL("unsupported getelementptr instruction: " << inst);
	return nullptr;
}
/**
* @brief Converts indices of LLVM getelementptr instruction.
*
* @param[in] base Pointed operand of LLVM getelementptr instruction converted
*                 to an expression in BIR.
* @param[in] start First index of LLVM getelementptr instruction to be converted.
* @param[in] end End of iterator through LLVM getelementptr instruction indices.
*/
ShPtr<Expression> LLVMInstructionConverter::convertGEPIndices(ShPtr<Expression> base,
		llvm::gep_type_iterator start, llvm::gep_type_iterator end) {
	auto indexOp = base;
	for (auto i = start; i != end; ++i) {
		auto index = getConverter()->convertValueToExpression(i.getOperand());
		if (i->isStructTy()) {
			auto indexInt = ucast<ConstInt>(index);
			indexOp = StructIndexOpExpr::create(indexOp, indexInt);
		} else {
			indexOp = ArrayIndexOpExpr::create(indexOp, index);
		}
	}

	return AddressOpExpr::create(indexOp);
}

/**
* @brief Returns the @c LLVMValueConverter.
*/
ShPtr<LLVMValueConverter> LLVMInstructionConverter::getConverter() {
	auto conv = converter.lock();
	ASSERT_MSG(conv, "LLVMValueConverter has not been set or no longer exists");
	return conv;
}

} // namespace llvmir2hll
} // namespace retdec
