/**
* @file src/bin2llvmir/analyses/traversal/bb_traversal_analysis.cpp
* @brief Implementation of basic block post-order traversal analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/SCCIterator.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/analyses/traversal/bb_traversal_analysis.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
* @brief Returns @c true if one of successor of @a bb is same basic block,
*        otherwise @c false.
*/
bool isBBLoop(BasicBlock &bb) {
	for (succ_iterator i = succ_begin(&bb), e = succ_end(&bb); i != e; ++i) {
		if (*i == &bb) {
			return true;
		}
	}

	return false;
}

} // anonymous namespace

/**
* @brief Emits linked list of basic blocks in post-order to standard error.
*
* Only for debugging purposes.
*/
void BBTraversalAnalysis::print() {
	errs() << "[BBTraversalAnalysis] Debug for linked list with basic blocks.\n";
	TraversalAnalysis::print();
}

/**
* @brief Constructs a new basic block traversal analysis.
*/
BBTraversalAnalysis::BBTraversalAnalysis() {}

/**
* @brief Destructs a basic block traversal analysis.
*/
BBTraversalAnalysis::~BBTraversalAnalysis() {}

/**
* @brief Runs basic block analysis and saves contained info.
*
* This method is need to run before methods that finds out results of this
* basic block analysis.
*
* @param[in] func Function which basic blocks are analyzed.
*/
void BBTraversalAnalysis::doBBsAnalysis(Function &func) {
	// If analysis was run before than now is need to clear everything.
	clear();

	Node *prevNode = nullptr;
	for (scc_iterator<Function *> i = scc_begin(&func), e = scc_end(&func);
			i != e; ++i) {
		const std::vector<llvm::BasicBlock*> &sccBBs(*i);
		if (sccBBs.size() > 1) {
			// We have strongly connected component. This means cycle basic
			// basic block dependency.
			prevNode = processBBsInSCC(sccBBs, prevNode);
			continue;
		}

		if (sccBBs.size() == 1) {
			if (isBBLoop(**sccBBs.begin())) {
				// Loop on same basic block.
				prevNode = processBBsInSCC(sccBBs, prevNode);
				continue;
			}

			// No recursion.
			prevNode = processBBNotInSCC(sccBBs, prevNode);
		}
	}

	// Set current node to initial state of analysis.
	currNode = headNode;
}

/**
* @brief Returns the next basic block, otherwise if all basic blocks were
*        returned than returns the null pointer.
*/
llvm::BasicBlock *BBTraversalAnalysis::getNextBB() {
	return cast_or_null<BasicBlock>(TraversalAnalysis::getNextVal());
}

/**
* @brief Returns next basic block that is part of some SCC.
*
* You have to use this method only if you know that next returned basic block
* will be part of some SCC. For this purpose to check use method
* @c isNextInSCC(). Than you can use this method more than once. To stop
* iterating through basic blocks in some SCC use @c stopIteratingSCC().
*/
llvm::BasicBlock *BBTraversalAnalysis::getNextBBInSCC() {
	return cast<BasicBlock>(TraversalAnalysis::getNextValInSCC());
}

/**
* @brief Processes basic blocks that are in SCC.
*
* Also creates nodes in linked list for basic blocks and connect them.
*
* @param[in] sccBBs Contains basic blocks that are in one SCC.
* @param[in] prevNode Previous node that was created.
*
* @return Created node which is the last in linked list.
*/
BBTraversalAnalysis::Node *BBTraversalAnalysis::processBBsInSCC(
		const std::vector<llvm::BasicBlock*> &sccBBs, Node *prevNode) {
	Node *firstSCCNode(nullptr);
	Node *newNode(nullptr);
	// Go through all basic blocks in SCC and create nodes for them.
	for (BasicBlock *bb : sccBBs) {
		newNode = Node::createNodeInSCC(*bb);
		solveConnectionWithNextNode(prevNode, newNode);
		if (bb == *sccBBs.begin()) {
			// Save first node because this node will be needed for create
			// backward connection.
			firstSCCNode = newNode;
		}
		prevNode = newNode;
	}
	// At the end we want to make a connection from last node to first.
	// A -> B -> C -> A. Backward connection signalizes SCC.
	prevNode->sccRevNode = firstSCCNode;

	// Return last created node.
	return prevNode;
}

/**
* @brief Processes basic block that is not in SCC.
*
* Also creates node in linked list for basic block and connect it.
*
* @param[in] sccBBs Contains basic block that is processed.
* @param[in] prevNode Previous node that was created.
*
* @return Created node which is the last in linked list.
*/
BBTraversalAnalysis::Node *BBTraversalAnalysis::processBBNotInSCC(
		const std::vector<llvm::BasicBlock*> &sccBBs, Node *prevNode) {
	Node *newNode = Node::createNodeNotInSCC(**sccBBs.begin());
	solveConnectionWithNextNode(prevNode, newNode);
	return newNode;
}

} // namespace bin2llvmir
} // namespace retdec
