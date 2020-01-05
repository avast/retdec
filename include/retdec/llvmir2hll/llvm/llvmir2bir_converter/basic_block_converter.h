/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter/basic_block_converter.h
* @brief A converter of LLVM basic blocks.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_BASIC_BLOCK_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_BASIC_BLOCK_CONVERTER_H

#include <llvm/IR/InstVisitor.h>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class BasicBlock;
class CallInst;
class InsertValueInst;
class Instruction;
class LoadInst;
class ReturnInst;
class StoreInst;
class UnreachableInst;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class LabelsHandler;
class LLVMValueConverter;
class Statement;

/**
* @brief A converter of LLVM basic blocks.
*
* This class converts only not inlinable instructions which are converted
* into statements.
*/
class BasicBlockConverter final: private retdec::utils::NonCopyable,
	private llvm::InstVisitor<BasicBlockConverter, Statement*> {
public:
	BasicBlockConverter(LLVMValueConverter* converter,
		LabelsHandler* labelsHandler);

	Statement* convert(llvm::BasicBlock &bb);

private:
	bool shouldBeConverted(const llvm::Instruction &inst) const;
	Statement* convertInstructionsOf(llvm::BasicBlock &bb);

	friend class llvm::InstVisitor<BasicBlockConverter, Statement*>;
	Statement* visitCallInst(llvm::CallInst &inst);
	Statement* visitInsertValueInst(llvm::InsertValueInst &inst);
	Statement* visitLoadInst(llvm::LoadInst &inst);
	Statement* visitReturnInst(llvm::ReturnInst &inst);
	Statement* visitStoreInst(llvm::StoreInst &inst);
	Statement* visitUnreachableInst(llvm::UnreachableInst &inst);
	Statement* visitInstruction(llvm::Instruction &inst);

	Statement* generateAssignOfPrevValForInsertValueInst(
		llvm::InsertValueInst &inst);

	/// A converter from LLVM values to values in BIR.
	LLVMValueConverter* converter = nullptr;

	/// A handler of labels.
	LabelsHandler* labelsHandler = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
