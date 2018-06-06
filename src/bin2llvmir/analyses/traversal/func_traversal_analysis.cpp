/**
* @file src/bin2llvmir/analyses/traversal/func_traversal_analysis.cpp
* @brief Implementation of post-order function traversal analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/SCCIterator.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/analyses/traversal/func_traversal_analysis.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
* @brief Emits linked list of functions in post-order to standard error.
*
* Only for debugging purposes.
*/
void FuncTraversalAnalysis::print() {
	errs() << "[FuncTraversalAnalysis] Debug for linked list with functions.\n";
	TraversalAnalysis::print();
}

/**
* @brief Constructs a new function traversal analysis.
*/
FuncTraversalAnalysis::FuncTraversalAnalysis() {}

/**
* @brief Destructs a function block traversal analysis.
*/
FuncTraversalAnalysis::~FuncTraversalAnalysis() {}

/**
* @brief Runs function analysis and saves contained info.
*
* This method is need to run before methods that finds out results of this
* function analysis.
*
* @param[in] callGraph Call graph of functions which are analyzed.
*/
void FuncTraversalAnalysis::doFuncsAnalysis(CallGraph &callGraph) {
	// If analysis was run before than now is need to clear everything.
	clear();

	CallGraphNode *startNode(callGraph.getExternalCallingNode());
	Node *prevNode = nullptr;
	for (scc_iterator<CallGraphNode *> i = scc_begin(startNode),
			e = scc_end(startNode); i != e; ++i) {
		const std::vector<llvm::CallGraphNode*> &callNodesVec(*i);
		if (callNodesVec.size() > 1) {
			// We have strongly connected component. This means recursion.
			prevNode = processFuncsInSCC(callNodesVec, prevNode);
			continue;
		}

		if (callNodesVec.size() == 1) {
			if (!(*callNodesVec.begin())->getFunction()) {
				// Some nodes in call graph are not function nodes. For example
				// starting external node. So skip them.
				continue;
			}

			if (i.hasLoop()) {
				// Self function recursion.
				prevNode = processFuncsInSCC(callNodesVec, prevNode);
				continue;
			}

			// No recursion.
			prevNode = processFuncNotInSCC(callNodesVec, prevNode);
		}
	}

	// Set current node to initial state of analysis.
	currNode = headNode;
}

/**
* @brief Returns the next function, otherwise if all functions were returned
*        than returns the null pointer.
*/
Function *FuncTraversalAnalysis::getNextFunc() {
	return cast_or_null<Function>(TraversalAnalysis::getNextVal());
}

/**
* @brief Returns next function that is part of some SCC.
*
* You have to use this method only if you know that next returned function will
* be part of some SCC. For this purpose to check use method @c isNextInSCC().
* Than you can use this method more than once. To stop iterating through
* functions in some SCC use @c stopIteratingSCC().
*/
Function *FuncTraversalAnalysis::getNextFuncInSCC() {
	return cast<Function>(TraversalAnalysis::getNextValInSCC());
}

/**
* @brief Processes functions that are in SCC.
*
* Also creates nodes in linked list for functions and connect them.
*
* @param[in] callNodesVec Contains functions that are in one SCC.
* @param[in] prevNode Previous node that was created.
*
* @return Created node which is the last in linked list.
*/
FuncTraversalAnalysis::Node *FuncTraversalAnalysis::processFuncsInSCC(
		const std::vector<llvm::CallGraphNode*> &callNodesVec, Node *prevNode) {
	Node *firstSCCNode(nullptr);
	Node *newNode(nullptr);
	for (CallGraphNode *callGraphNode : callNodesVec) {
		// Go through all functions in SCC and create nodes for them.
		newNode = Node::createNodeInSCC(*callGraphNode->getFunction());
		solveConnectionWithNextNode(prevNode, newNode);
		if (callGraphNode == *callNodesVec.begin()) {
			// Save first node because this node will be needed for create
			// backward connection.
			firstSCCNode = newNode;
		}
		prevNode = newNode;
	}
	// At the end we want to make an connection from last node to first.
	// A -> B -> C -> A. Backward connection signalizes SCC.
	prevNode->sccRevNode = firstSCCNode;

	// Return last created node.
	return prevNode;
}

/**
* @brief Processes function that is not in SCC.
*
* Also creates node in linked list for basic block and connect it.
*
* @param[in] callNodesVec Contains function that is processed.
* @param[in] prevNode Previous node that was created.
*
* @return Created node which is the last in linked list.
*/
FuncTraversalAnalysis::Node *FuncTraversalAnalysis::processFuncNotInSCC(
		const std::vector<llvm::CallGraphNode*> &callNodesVec, Node *prevNode) {
	Node *newNode = Node::createNodeNotInSCC(
		*(*callNodesVec.begin())->getFunction());
	solveConnectionWithNextNode(prevNode, newNode);
	return newNode;
}

} // namespace bin2llvmir
} // namespace retdec
