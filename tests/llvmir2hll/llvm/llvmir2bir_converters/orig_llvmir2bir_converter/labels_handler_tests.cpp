/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler_tests.cpp
* @brief Tests for the @c labels_handler module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/LLVMContext.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c labels_handler module.
*/
class LabelsHandlerTests: public Test {
protected:
	UPtr<llvm::BasicBlock> createBasicBlock(const std::string &name);

protected:
	/// Context for the LLVM module.
	// Implementation note: Do NOT use llvm::getGlobalContext() because that
	//                      would make the context same for all tests (we want
	//                      to run all tests in isolation).
	llvm::LLVMContext llvmContext;

	LabelsHandler handler;
};

/**
* @brief Creates a new basic block with the given name.
*/
UPtr<llvm::BasicBlock> LabelsHandlerTests::createBasicBlock(
		const std::string &name) {
	return UPtr<llvm::BasicBlock>(
		llvm::BasicBlock::Create(llvmContext, name)
	);
}

TEST_F(LabelsHandlerTests,
GetLabelOfReturnsCorrectValueWhenBasicBlockHasAddress) {
	auto bb = createBasicBlock("dec_label_pc_110ab54");

	ASSERT_EQ("0x110ab54", handler.getLabel(bb.get()));
}

TEST_F(LabelsHandlerTests,
GetLabelOfReturnsNameOfBasicBlockWhenItDoesNotHaveAddress) {
	auto bb = createBasicBlock("my_block");

	ASSERT_EQ("my_block", handler.getLabel(bb.get()));
}

TEST_F(LabelsHandlerTests,
SetGotoTargetLabelSetsCorrectLabelWhenBasicBlockHasAddress) {
	auto target = EmptyStmt::create();
	auto targetBB = createBasicBlock("dec_label_pc_110ab54");

	handler.setGotoTargetLabel(target, targetBB.get());

	ASSERT_EQ("0x110ab54", target->getLabel());
}

TEST_F(LabelsHandlerTests,
SetGotoTargetLabelSetsCorrectLabelWhenBasicBlockDoesNotHaveAddress) {
	auto target = EmptyStmt::create();
	auto targetBB = createBasicBlock("my_block");

	handler.setGotoTargetLabel(target, targetBB.get());

	ASSERT_EQ("my_block", target->getLabel());
}

TEST_F(LabelsHandlerTests,
SetGotoTargetLabelEnsuresLabelIsValid) {
	auto target = EmptyStmt::create();
	auto targetBB = createBasicBlock("a.b");

	handler.setGotoTargetLabel(target, targetBB.get());

	ASSERT_EQ("a_b", target->getLabel());
}

TEST_F(LabelsHandlerTests,
SetGotoTargetLabelEnsuresLabelIsUnique) {
	auto target1 = EmptyStmt::create();
	auto targetBB1 = createBasicBlock("my_block");
	handler.setGotoTargetLabel(target1, targetBB1.get());
	auto target2 = EmptyStmt::create();
	auto targetBB2 = createBasicBlock("my_block");

	handler.setGotoTargetLabel(target2, targetBB2.get());

	ASSERT_EQ("my_block_2", target2->getLabel());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
