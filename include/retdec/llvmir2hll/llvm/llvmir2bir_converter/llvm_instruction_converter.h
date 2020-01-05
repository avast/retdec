/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter/llvm_instruction_converter.h
* @brief A converter from LLVM instruction to expression in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_LLVM_INSTRUCTION_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_LLVM_INSTRUCTION_CONVERTER_H

#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/InstVisitor.h>

#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/llvm_fcmp_converter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class AddrSpaceCastInst;
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
	private llvm::InstVisitor<LLVMInstructionConverter, Expression*> {
public:
	/// @name Constant expression conversion
	/// @{
	Expression* convertConstExprToExpression(llvm::ConstantExpr *cExpr);
	/// @}

	/// @name Instruction conversion
	/// @{
	Expression* convertInstructionToExpression(llvm::Instruction *inst);
	CallExpr* convertCallInstToCallExpr(llvm::CallInst &inst);
	Expression* generateAccessToAggregateType(llvm::CompositeType *type,
		Expression* base, const llvm::ArrayRef<unsigned> &indices);
	/// @}

	/// @name Options
	/// @{
	void setLLVMValueConverter(LLVMValueConverter* conv);
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

private:
	/// @name Instruction conversion using InstVisitor
	/// @{
	friend class llvm::InstVisitor<LLVMInstructionConverter, Expression*>;
	Expression* visitAddrSpaceCastInst(llvm::AddrSpaceCastInst &inst);
	Expression* visitBinaryOperator(llvm::BinaryOperator &inst);
	Expression* visitBitCastInst(llvm::BitCastInst &inst);
	Expression* visitFPExtInst(llvm::FPExtInst &inst);
	Expression* visitSExtInst(llvm::SExtInst &inst);
	Expression* visitZExtInst(llvm::ZExtInst &inst);
	Expression* visitFPToSIInst(llvm::FPToSIInst &inst);
	Expression* visitFPToUIInst(llvm::FPToUIInst &inst);
	Expression* visitTruncInst(llvm::TruncInst &inst);
	Expression* visitFPTruncInst(llvm::FPTruncInst &inst);
	Expression* visitIntToPtrInst(llvm::IntToPtrInst &inst);
	Expression* visitPtrToIntInst(llvm::PtrToIntInst &inst);
	Expression* visitSIToFPInst(llvm::SIToFPInst &inst);
	Expression* visitUIToFPInst(llvm::UIToFPInst &inst);
	Expression* visitICmpInst(llvm::ICmpInst &inst);
	Expression* visitFCmpInst(llvm::FCmpInst &inst);
	Expression* visitSelectInst(llvm::SelectInst &inst);
	Expression* visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
	Expression* visitExtractValueInst(llvm::ExtractValueInst &inst);
	Expression* visitInstruction(llvm::Instruction &inst);
	/// @}

	Expression* convertBinaryOpToExpression(llvm::User &inst,
		unsigned opcode);
	Expression* convertICmpInstToExpression(llvm::User &inst,
		unsigned predicate);
	Expression* convertFCmpInstToExpression(llvm::User &inst,
		unsigned predicate);
	Expression* convertSelectInstToExpression(llvm::User &inst);
	Expression* convertExtCastInstToExpression(llvm::User &inst,
		ExtCastExpr::Variant variant);
	Expression* convertIntToFPInstToExpression(llvm::User &inst,
		IntToFPCastExpr::Variant variant);
	Expression* convertFPToIntInstToExpression(llvm::User &inst);
	Expression* convertTruncInstToExpression(llvm::User &inst);
	template<class T>
	Expression* convertCastInstToExpression(llvm::User &inst);
	Expression* convertGetElementPtrToExpression(llvm::User &inst);
	Expression* convertGEPIndices(Expression* base,
		llvm::gep_type_iterator start, llvm::gep_type_iterator end);

	LLVMValueConverter* getConverter();

	/// A converter from LLVM values to values in BIR.
	LLVMValueConverter* converter = nullptr;

	/// A converter from LLVM fcmp instruction to expression in BIR.
	LLVMFCmpConverter fcmpConverter;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
