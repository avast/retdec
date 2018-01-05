/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/cfg_node_tests.cpp
* @brief Tests for the @c cfg_node.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>
#include <llvm/ADT/Twine.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/cfg_node.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c cfg_node.
*/
class CFGNodeTests: public ::testing::Test {
protected:
	/// Context for the LLVM module.
	llvm::LLVMContext context;
};

//
// Tests for constructor
//

TEST_F(CFGNodeTests,
CreatedCFGNodeHasTheSameFirstAndLastBB) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(bb, node->getFirstBB());
	ASSERT_EQ(bb, node->getLastBB());
}

TEST_F(CFGNodeTests,
CreatedCFGNodeHasCorrectlySetBody) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	auto nodeBody = node->getBody();
	ASSERT_TRUE(nodeBody);
	ASSERT_BIR_EQ(body, nodeBody);
	ASSERT_FALSE(nodeBody->getSuccessor());
}

//
// Tests for setLastBB()
//

TEST_F(CFGNodeTests,
SetLastBBSetsOnlyLastBB) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto node = std::make_shared<CFGNode>(bb1, body1);

	node->setLastBB(bb2);

	ASSERT_EQ(bb1, node->getFirstBB());
	ASSERT_EQ(bb2, node->getLastBB());
}

//
// Tests for getTerm()
//

TEST_F(CFGNodeTests,
GetTermReturnsTerminatorInstructionOfLastBB) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto termInst = llvm::ReturnInst::Create(context, nullptr, bb);
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(termInst, node->getTerm());
}

//
// Tests for getCond()
//

TEST_F(CFGNodeTests,
GetCondReturnsCorrectCorrectCondValueForBranchInst) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto type = llvm::Type::getInt1Ty(context);
	auto cond = new llvm::Argument(type, "cond");
	llvm::BranchInst::Create(bb2, bb3, cond, bb);
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(cond, node->getCond());
}

TEST_F(CFGNodeTests,
GetCondReturnsCorrectCorrectCondValueForSwitchInst) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto bb2 = llvm::BasicBlock::Create(context, "default");
	auto type = llvm::Type::getInt32Ty(context);
	auto cond = new llvm::Argument(type, "cond");
	llvm::SwitchInst::Create(cond, bb2, 0, bb);
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(cond, node->getCond());
}

//
// Tests for setBody()
//

TEST_F(CFGNodeTests,
SetBodyOverridesTheCurrentBody) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto body2 = EmptyStmt::create();
	auto node = std::make_shared<CFGNode>(bb, body1);

	node->setBody(body2);

	auto nodeBody = node->getBody();
	ASSERT_TRUE(nodeBody);
	ASSERT_BIR_EQ(body2, nodeBody);
	ASSERT_FALSE(nodeBody->getSuccessor());
}

//
// Tests for appendToBody()
//

TEST_F(CFGNodeTests,
AppendToBodyAppendStatementsToTheCurrentBodyCorrectly) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto body2 = EmptyStmt::create();
	auto node = std::make_shared<CFGNode>(bb, body1);

	node->appendToBody(body2);

	auto nodeBody = node->getBody();
	ASSERT_TRUE(nodeBody);
	ASSERT_BIR_EQ(body1, nodeBody);
	auto succ = nodeBody->getSuccessor();
	ASSERT_TRUE(succ);
	ASSERT_BIR_EQ(body2, succ);
	ASSERT_FALSE(succ->getSuccessor());
}

//
// Tests for addSuccessor() and getSucc()
//

TEST_F(CFGNodeTests,
NodeHasTwoPredecessorsAfterBeingAddedAsSuccessorToTwoOtherNodes) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);

	node1->addSuccessor(node3);
	node2->addSuccessor(node3);

	ASSERT_EQ(2, node3->getPredsNum());
}

TEST_F(CFGNodeTests,
AfterAddSuccessorGetSuccReturnsCorrectSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_BIR_EQ(node2, node1->getSucc(0));
}

TEST_F(CFGNodeTests,
AfterTwoCallsOfAddSuccessorGetSuccReturnsCorrectSuccessorsInOrderTheyHaveBeenAdded) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);

	node1->addSuccessor(node2);
	node1->addSuccessor(node3);

	ASSERT_BIR_EQ(node2, node1->getSucc(0));
	ASSERT_BIR_EQ(node3, node1->getSucc(1));
}

//
// Tests for getPredsNum()
//

TEST_F(CFGNodeTests,
EmptyNodeHasZeroPredecessors) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(0, node->getPredsNum());
}

TEST_F(CFGNodeTests,
NodeHasOnePredecessorAfterBeingAddedAsSuccessorToOtherNode) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_EQ(1, node2->getPredsNum());
}

TEST_F(CFGNodeTests,
NodeHasOnePredecessorAfterBeingAddedAsSuccessorToOtherNodeTwice) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);
	node1->addSuccessor(node2);

	ASSERT_EQ(1, node2->getPredsNum());
}

//
// Tests for getSuccNum()
//

TEST_F(CFGNodeTests,
EmptyNodeHasZeroSuccessors) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(0, node->getSuccNum());
}

TEST_F(CFGNodeTests,
EmptyNodeHasOneSuccessorAfterAddSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_EQ(1, node1->getSuccNum());
}

TEST_F(CFGNodeTests,
EmptyNodeHasTwoSuccessorsAfterTwoCallsOfAddSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);

	node1->addSuccessor(node2);
	node1->addSuccessor(node3);

	ASSERT_EQ(2, node1->getSuccNum());
}

//
// Tests for getSuccessors()
//

TEST_F(CFGNodeTests,
GetSuccessorsReturnsEmptyVectorForEmptyNode) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	const auto &successors = node->getSuccessors();
	ASSERT_TRUE(successors.empty());
}

TEST_F(CFGNodeTests,
GetSuccessorsReturnsVectorWithOneNodeForNodeWithOneSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	const auto &successors = node1->getSuccessors();
	ASSERT_EQ(1, successors.size());
	ASSERT_BIR_EQ(node2, successors.at(0));
}

TEST_F(CFGNodeTests,
GetSuccessorsReturnsVectorWithTwoNodesInCorrectOrderForNodeWithTwoSuccessors) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);

	node1->addSuccessor(node2);
	node1->addSuccessor(node3);

	const auto &successors = node1->getSuccessors();
	ASSERT_EQ(2, successors.size());
	ASSERT_BIR_EQ(node2, successors.at(0));
	ASSERT_BIR_EQ(node3, successors.at(1));
}

//
// Tests for hasSuccessor()
//

TEST_F(CFGNodeTests,
HasSuccessorReturnsTrueToNodeWhichIsSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_TRUE(node1->hasSuccessor(node2));
}

TEST_F(CFGNodeTests,
HasSuccessorReturnsFalseToNodeWhichIsNotSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_FALSE(node1->hasSuccessor(node1));
}

//
// Tests for getSuccOrNull()
//

TEST_F(CFGNodeTests,
GetSuccOrNullReturnsCorrectSuccessorWhenSuccessorExists) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_BIR_EQ(node2, node1->getSuccOrNull(0));
}

TEST_F(CFGNodeTests,
GetSuccOrNullReturnsNullPtrWhenSuccessorDoesNotExist) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ(nullptr, node->getSuccOrNull(0));
}

//
// Tests for removeSucc()
//

TEST_F(CFGNodeTests,
RemoveSuccCorrectlyRemovesNodeFromSuccessorsAndSelfFromNodesPredecessors) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);
	auto bb4 = llvm::BasicBlock::Create(context, "after1Pred");
	auto body4 = EmptyStmt::create();
	auto node4 = std::make_shared<CFGNode>(bb4, body4);
	auto bb5 = llvm::BasicBlock::Create(context, "after1Succ");
	auto body5 = EmptyStmt::create();
	auto node5 = std::make_shared<CFGNode>(bb5, body5);
	node1->addSuccessor(node2);
	node1->addSuccessor(node3);
	node4->addSuccessor(node2);
	node2->addSuccessor(node5);

	node1->removeSucc(0);

	ASSERT_EQ(1, node1->getSuccNum());
	ASSERT_TRUE(node1->hasSuccessor(node3));
	ASSERT_EQ(1, node2->getPredsNum());
	ASSERT_EQ(1, node4->getSuccNum());
	ASSERT_TRUE(node4->hasSuccessor(node2));
	ASSERT_EQ(1, node5->getPredsNum());
	ASSERT_EQ(1, node2->getSuccNum());
	ASSERT_TRUE(node2->hasSuccessor(node5));
}

//
// Tests for deleteSucc()
//

TEST_F(CFGNodeTests,
DeleteSuccCorrectlyRemovesNodeFromSuccessorsAndRemovesAllItsSuccs) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);
	auto bb4 = llvm::BasicBlock::Create(context, "after1Succ");
	auto body4 = EmptyStmt::create();
	auto node4 = std::make_shared<CFGNode>(bb4, body4);
	node1->addSuccessor(node2);
	node1->addSuccessor(node3);
	node2->addSuccessor(node4);

	node1->deleteSucc(0);

	ASSERT_EQ(1, node1->getSuccNum());
	ASSERT_TRUE(node1->hasSuccessor(node3));
	ASSERT_EQ(0, node2->getPredsNum());
	ASSERT_EQ(0, node2->getSuccNum());
	ASSERT_EQ(0, node4->getPredsNum());
}

//
// Tests for deleteSuccessors()
//

TEST_F(CFGNodeTests,
DeleteSuccCorrectlyRemovesAllSuccessorsAndRemovesAllTheirSuccs) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after1");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "after2");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);
	auto bb4 = llvm::BasicBlock::Create(context, "after1Succ");
	auto body4 = EmptyStmt::create();
	auto node4 = std::make_shared<CFGNode>(bb4, body4);
	node1->addSuccessor(node2);
	node1->addSuccessor(node3);
	node2->addSuccessor(node4);

	node1->deleteSuccessors();

	ASSERT_EQ(0, node1->getSuccNum());
	ASSERT_EQ(0, node2->getPredsNum());
	ASSERT_EQ(0, node2->getSuccNum());
	ASSERT_EQ(0, node4->getPredsNum());
}

//
// Tests for moveSuccessorsFrom()
//

TEST_F(CFGNodeTests,
MoveSuccessorsFromCorrectlyMovesAllSuccessorsFromTheGivenNodeToThisNode) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "afterSucc1");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);
	auto bb4 = llvm::BasicBlock::Create(context, "afterSucc2");
	auto body4 = EmptyStmt::create();
	auto node4 = std::make_shared<CFGNode>(bb4, body4);
	node1->addSuccessor(node2);
	node2->addSuccessor(node3);
	node2->addSuccessor(node4);

	node1->moveSuccessorsFrom(node2);

	ASSERT_EQ(2, node1->getSuccNum());
	ASSERT_TRUE(node1->hasSuccessor(node3));
	ASSERT_TRUE(node1->hasSuccessor(node4));
}

//
// Tests for markAsBackEdge() and isBackEdge()
//

TEST_F(CFGNodeTests,
IsBackEdgeReturnFalseWhenSuccessorIsNotMarkedAsBackEdge) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);

	ASSERT_FALSE(node1->isBackEdge(node2));
}

TEST_F(CFGNodeTests,
IsBackEdgeReturnTrueWhenSuccessorIsMarkedAsBackEdge) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->addSuccessor(node2);
	node1->markAsBackEdge(node2);

	ASSERT_TRUE(node1->isBackEdge(node2));
}

//
// Tests for setStatementSuccessor() and getStatementSuccessor()
//

TEST_F(CFGNodeTests,
AfterAddStatementSuccessorGetStatementSuccesssorReturnsCorrectNode) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->setStatementSuccessor(node2);

	ASSERT_BIR_EQ(node2, node1->getStatementSuccessor());
}

TEST_F(CFGNodeTests,
NodeHasOnePredecessorAfterBeingAddedAsStatementSuccessorToOtherNode) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->setStatementSuccessor(node2);

	ASSERT_EQ(1, node2->getPredsNum());
}

//
// Tests for hasStatementSuccessor()
//

TEST_F(CFGNodeTests,
EmptyNodeDoesNotHaveStatementSuccessor) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_FALSE(node->hasStatementSuccessor());
}

TEST_F(CFGNodeTests,
AfterAddStatementSuccessorHasStatementSuccesssorReturnsTrue) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);

	node1->setStatementSuccessor(node2);

	ASSERT_TRUE(node1->hasStatementSuccessor());
}

//
// Tests for removeStatementSuccessor()
//

TEST_F(CFGNodeTests,
RemoveStatementSuccessorCorrectlyRemovesStatementSuccessor) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	node1->setStatementSuccessor(node2);

	node1->removeStatementSuccessor();

	ASSERT_FALSE(node1->hasStatementSuccessor());
	ASSERT_EQ(0, node2->getPredsNum());
}

TEST_F(CFGNodeTests,
WhenStatementSuccessorIsRedefinedTheFormerIsCorrectlyRemoved) {
	auto bb1 = llvm::BasicBlock::Create(context, "entry");
	auto body1 = EmptyStmt::create();
	auto node1 = std::make_shared<CFGNode>(bb1, body1);
	auto bb2 = llvm::BasicBlock::Create(context, "after");
	auto body2 = EmptyStmt::create();
	auto node2 = std::make_shared<CFGNode>(bb2, body2);
	auto bb3 = llvm::BasicBlock::Create(context, "newAfter");
	auto body3 = EmptyStmt::create();
	auto node3 = std::make_shared<CFGNode>(bb3, body3);
	node1->setStatementSuccessor(node2);

	node1->setStatementSuccessor(node3);

	ASSERT_EQ(0, node2->getPredsNum());
}

//
// Tests for getName()
//

TEST_F(CFGNodeTests,
GetNameReturnCorrectNameOfFirstBBInsideNode) {
	auto bb = llvm::BasicBlock::Create(context, "entry");
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ("entry"s, node->getName());
}

TEST_F(CFGNodeTests,
GetNameReturnUnnamedForNodeWithFirstBBWithoutName) {
	auto bb = llvm::BasicBlock::Create(context);
	auto body = EmptyStmt::create();

	auto node = std::make_shared<CFGNode>(bb, body);

	ASSERT_EQ("<unnamed>"s, node->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
