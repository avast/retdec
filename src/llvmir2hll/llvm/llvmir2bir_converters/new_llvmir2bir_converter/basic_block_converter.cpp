/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/basic_block_converter.cpp
* @brief Implementation of BasicBlockConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/basic_block_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new basic block converter.
*
* @param[in] converter A converter from LLVM values to values in BIR.
* @param[in] labelsHandler A handler of labels.
*/
BasicBlockConverter::BasicBlockConverter(ShPtr<LLVMValueConverter> converter,
	ShPtr<LabelsHandler> labelsHandler):
		converter(converter), labelsHandler(labelsHandler) {}

/**
* @brief Destructs the converter.
*/
BasicBlockConverter::~BasicBlockConverter() {}

/**
* @brief Converts the given LLVM basic block @a bb into a sequence of statements
*        in BIR.
*/
ShPtr<Statement> BasicBlockConverter::convert(llvm::BasicBlock &bb) {
	auto convertedBody = convertInstructionsOf(bb);
	if (!convertedBody) {
		convertedBody = EmptyStmt::create();
	}

	convertedBody->setMetadata(labelsHandler->getLabel(&bb));
	return convertedBody;
}

/**
* @brief Determines whether the given LLVM instruction @a inst should be
*        converted by BasicBlockConverter.
*
* Following instruction shouldn't be converted:
*  - Inlinable instructions - reason is that these instructions are inlined
*    as operands in other instructions.
*  - Direct allocations - reason is that variable is created, when it is used
*    for the first time and variable definitions are appended to the beginning
*    of the function for all defined variables.
*  - Branch and switch instructions - reason is that branch instructions are
*    handled by StructureConverter.
*  - PHI nodes - reason is that PHI nodes have to be converted multiple times, at
*    the end of the basic block which is followed by basic block with PHI node.
*/
bool BasicBlockConverter::shouldBeConverted(const llvm::Instruction &inst) const {
	return !LLVMSupport::isInlinableInst(&inst)
		&& !LLVMSupport::isDirectAlloca(&inst)
		&& !llvm::isa<llvm::BranchInst>(inst)
		&& !llvm::isa<llvm::PHINode>(inst)
		&& !llvm::isa<llvm::SwitchInst>(inst);
}

/**
* @brief Converts instruction of the given LLVM basic block @a bb into
*        a sequence of statements in BIR.
*/
ShPtr<Statement> BasicBlockConverter::convertInstructionsOf(llvm::BasicBlock &bb) {
	ShPtr<Statement> firstStmt;
	for (auto &inst: bb.getInstList()) {
		if (shouldBeConverted(inst)) {
			auto stmt = visit(inst);
			firstStmt = Statement::mergeStatements(firstStmt, stmt);
		}
	}

	return firstStmt;
}
/**
* @brief Converts the given LLVM call instruction @a inst into a statement in BIR.
*
* If function result is used somewhere, an assign statement will be created.
* Otherwise, a call statement will be created.
*/
ShPtr<Statement> BasicBlockConverter::visitCallInst(llvm::CallInst &inst) {
	auto callExpr = converter->convertCallInstToCallExpr(inst);

	if (inst.hasNUses(0)) {
		return CallStmt::create(callExpr);
	}

	auto lhs = converter->convertValueToVariable(&inst);
	return AssignStmt::create(lhs, callExpr);
}

/**
* @brief Converts the given LLVM insertvalue instruction @a inst into two assign
*        statements in BIR.
*
* The reason why this instruction is converted into two statements is that
* this instruction does two operations: Inserts value to the specified position
* of the composite and returns new composite with inserted value (original
* composite remains unchanged).
*
* Example code in LLVM IR:
* @code
* define void @function([10 x i32] %arr, i32 %value) {
*     %a = insertvalue [10 x i32] %arr, i32 %value, 3
*     ; ...
* }
* @endcode
*
* The example code is converted into following code in BIR:
* @code
* function(a[10] arr, int value) {
*     int a[10];
*     a = arr;
*     a[3] = value;
*     // ...
* }
* @endcode
*/
ShPtr<Statement> BasicBlockConverter::visitInsertValueInst(llvm::InsertValueInst &inst) {
	auto type = llvm::cast<llvm::CompositeType>(inst.getAggregateOperand()->getType());
	auto base = converter->convertValueToExpression(&inst);

	auto lhs = converter->generateAccessToAggregateType(type, base, inst.getIndices());
	auto rhs = converter->convertValueToExpression(inst.getInsertedValueOperand());
	auto assignStmt = AssignStmt::create(lhs, rhs);

	auto varDef = generateAssignOfPrevValForInsertValueInst(inst);
	varDef->setSuccessor(assignStmt);
	return varDef;
}

/**
* @brief Converts the given LLVM load instruction @a inst into an assign
*        statement in BIR.
*/
ShPtr<Statement> BasicBlockConverter::visitLoadInst(llvm::LoadInst &inst) {
	auto lhs = converter->convertValueToVariable(&inst);
	if (inst.isVolatile()) {
		lhs->markAsExternal();
	}

	auto rhs = converter->convertValueToDerefExpression(inst.getPointerOperand());
	return AssignStmt::create(lhs, cast<Expression>(rhs));
}

/**
* @brief Converts the given LLVM return instruction @a inst into a statement in BIR.
*/
ShPtr<Statement> BasicBlockConverter::visitReturnInst(llvm::ReturnInst &inst) {
	if (inst.getNumOperands() == 0) {
		return ReturnStmt::create();
	}

	auto retVal = converter->convertValueToExpression(inst.getReturnValue());
	return ReturnStmt::create(retVal);
}

/**
* @brief Converts the given LLVM store instruction @a inst into an assign
*        statement in BIR.
*/
ShPtr<Statement> BasicBlockConverter::visitStoreInst(llvm::StoreInst &inst) {
	auto lhs = converter->convertValueToDerefExpression(inst.getPointerOperand());
	if (inst.isVolatile()) {
		if (auto lhsVar = cast<Variable>(lhs)) {
			lhsVar->markAsExternal();
		}
	}

	auto rhs = converter->convertValueToExpression(inst.getValueOperand());
	return AssignStmt::create(lhs, rhs);
}

/**
* @brief Converts the given LLVM @c unreachable instruction @a inst into an
*        unreachable statement in BIR.
*/
ShPtr<Statement> BasicBlockConverter::visitUnreachableInst(llvm::UnreachableInst &inst) {
	return UnreachableStmt::create();
}

/**
* @brief Converts the given LLVM instruction @a inst into an assign statement in
*        BIR. This method converts other instructions.
*/
ShPtr<Statement> BasicBlockConverter::visitInstruction(llvm::Instruction &inst) {
	auto lhs = converter->convertValueToVariable(&inst);
	auto rhs = converter->convertInstructionToExpression(&inst);
	return AssignStmt::create(lhs, rhs);
}

/**
* @brief Generates assignment of previous value to aggregate type expression
*        for the given LLVM insertvalue instruction @a inst.
*/
ShPtr<Statement> BasicBlockConverter::generateAssignOfPrevValForInsertValueInst(
		llvm::InsertValueInst &inst) {
	auto base = converter->convertValueToExpression(&inst);
	auto prevVal = converter->convertValueToExpression(inst.getAggregateOperand());
	return AssignStmt::create(base, prevVal);
}

} // namespace llvmir2hll
} // namespace retdec
