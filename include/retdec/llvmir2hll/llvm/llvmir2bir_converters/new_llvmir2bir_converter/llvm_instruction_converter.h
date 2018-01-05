/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_instruction_converter.h
* @brief A converter from LLVM instruction to expression in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_INSTRUCTION_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_INSTRUCTION_CONVERTER_H

#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/InstVisitor.h>

#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class BinaryOperator;
class BitCastInst;
class CallInst;
class CompositeType;
class ConstantExpr;
class ExtractValueInst;
class FCmpInst;
class FPExtInst;
class FPToSIInst;
class FPToUIInst;
class FPTruncInst;
class GetElementPtrInst;
class ICmpInst;
class Instruction;
class IntToPtrInst;
class PtrToIntInst;
class SelectInst;
class SExtInst;
class SIToFPInst;
class TruncInst;
class UIToFPInst;
class User;
class ZExtInst;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class CallExpr;
class Expression;
class LLVMFCmpConverter;
class LLVMValueConverter;

/**
* @brief A converter from LLVM instruction to expression in BIR.
*
* This class converts only inlinable instructions which are converted
* into expressions.
*
* @par Preconditions
*  - @c LLVMValueConverter must be set
*/
class LLVMInstructionConverter final: private retdec::utils::NonCopyable,
	private llvm::InstVisitor<LLVMInstructionConverter, ShPtr<Expression>> {
public:
	LLVMInstructionConverter();
	~LLVMInstructionConverter();

	/// @name Constant expression conversion
	/// @{
	ShPtr<Expression> convertConstExprToExpression(llvm::ConstantExpr *cExpr);
	/// @}

	/// @name Instruction conversion
	/// @{
	ShPtr<Expression> convertInstructionToExpression(llvm::Instruction *inst);
	ShPtr<CallExpr> convertCallInstToCallExpr(llvm::CallInst &inst);
	ShPtr<Expression> generateAccessToAggregateType(llvm::CompositeType *type,
		const ShPtr<Expression> &base, const llvm::ArrayRef<unsigned> &indices);
	/// @}

	/// @name Options
	/// @{
	void setLLVMValueConverter(ShPtr<LLVMValueConverter> conv);
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

private:
	/// @name Instruction conversion using InstVisitor
	/// @{
	friend class llvm::InstVisitor<LLVMInstructionConverter, ShPtr<Expression>>;
	ShPtr<Expression> visitBinaryOperator(llvm::BinaryOperator &inst);
	ShPtr<Expression> visitBitCastInst(llvm::BitCastInst &inst);
	ShPtr<Expression> visitFPExtInst(llvm::FPExtInst &inst);
	ShPtr<Expression> visitSExtInst(llvm::SExtInst &inst);
	ShPtr<Expression> visitZExtInst(llvm::ZExtInst &inst);
	ShPtr<Expression> visitFPToSIInst(llvm::FPToSIInst &inst);
	ShPtr<Expression> visitFPToUIInst(llvm::FPToUIInst &inst);
	ShPtr<Expression> visitTruncInst(llvm::TruncInst &inst);
	ShPtr<Expression> visitFPTruncInst(llvm::FPTruncInst &inst);
	ShPtr<Expression> visitIntToPtrInst(llvm::IntToPtrInst &inst);
	ShPtr<Expression> visitPtrToIntInst(llvm::PtrToIntInst &inst);
	ShPtr<Expression> visitSIToFPInst(llvm::SIToFPInst &inst);
	ShPtr<Expression> visitUIToFPInst(llvm::UIToFPInst &inst);
	ShPtr<Expression> visitICmpInst(llvm::ICmpInst &inst);
	ShPtr<Expression> visitFCmpInst(llvm::FCmpInst &inst);
	ShPtr<Expression> visitSelectInst(llvm::SelectInst &inst);
	ShPtr<Expression> visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
	ShPtr<Expression> visitExtractValueInst(llvm::ExtractValueInst &inst);
	ShPtr<Expression> visitInstruction(llvm::Instruction &inst);
	/// @}

	ShPtr<Expression> convertBinaryOpToExpression(llvm::User &inst,
		unsigned opcode);
	ShPtr<Expression> convertICmpInstToExpression(llvm::User &inst,
		unsigned predicate);
	ShPtr<Expression> convertFCmpInstToExpression(llvm::User &inst,
		unsigned predicate);
	ShPtr<Expression> convertSelectInstToExpression(llvm::User &inst);
	ShPtr<Expression> convertExtCastInstToExpression(llvm::User &inst,
		ExtCastExpr::Variant variant);
	ShPtr<Expression> convertIntToFPInstToExpression(llvm::User &inst,
		IntToFPCastExpr::Variant variant);
	ShPtr<Expression> convertFPToIntInstToExpression(llvm::User &inst);
	ShPtr<Expression> convertTruncInstToExpression(llvm::User &inst);
	template<class T>
	ShPtr<Expression> convertCastInstToExpression(llvm::User &inst);
	ShPtr<Expression> convertGetElementPtrToExpression(llvm::User &inst);
	ShPtr<Expression> convertGEPIndices(ShPtr<Expression> base,
		llvm::gep_type_iterator start, llvm::gep_type_iterator end);

	ShPtr<LLVMValueConverter> getConverter();

	/// A converter from LLVM values to values in BIR.
	WkPtr<LLVMValueConverter> converter;

	/// A converter from LLVM fcmp instruction to expression in BIR.
	UPtr<LLVMFCmpConverter> fcmpConverter;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
