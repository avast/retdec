/**
* @file src/bin2llvmir/analyses/traversal/traversal_analysis.cpp
* @brief Implementation of base class for traversal analyses.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/analyses/traversal/traversal_analysis.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
* @brief Emits linked list of items in post-order to standard error.
*
* Only for debugging purposes.
*/
void TraversalAnalysis::print() {
	errs() << "-----------------------------------------------\n";
	Node *node(headNode);
	while (node != nullptr) {
		errs() << "Debug info of node for: '" <<
			node->value.getName() << "':\n";
		if (node->isInSCC) {
			errs() << "     Item 'is' part of SCC\n";
		} else {
			errs() << "     Item 'is not' part of SCC\n";

		}
		if (node->sccRevNode != nullptr) {
			errs() << "     Start item of SCC: '" <<
				node->sccRevNode->value.getName() << "'\n";
		}
		if (node->nextNode != nullptr) {
			errs() << "     Successor item: '" <<
				node->nextNode->value.getName() << "'\n";
		}
		node = node->nextNode;
	}
}

/**
* @brief Constructs a new traversal analysis.
*/
TraversalAnalysis::TraversalAnalysis(): headNode(nullptr), currNode(nullptr),
	causesNextNewSCCIter(false) {}

/**
* @brief Destructs a traversal analysis.
*/
TraversalAnalysis::~TraversalAnalysis() {
	clear();
}

/**
* @brief Returns the next value, otherwise if all values were returned than
*        returns the null pointer.
*/
Value *TraversalAnalysis::getNextVal() {
	if (currNode == nullptr) {
		// All values returned.
		return nullptr;
	}
	Value &value(currNode->value);
	// Set current node to next node.
	currNode = currNode->nextNode;

	return &value;
}

/**
* @brief Returns the next value that is part of some SCC.
*
* @par Preconditions
*  - Next value have to be in SCC.
*/
Value *TraversalAnalysis::getNextValInSCC() {
	assert(currNode->isInSCC && "Use only on items that are part of some SCC");
	Value &value(currNode->value);
	if (currNode->sccRevNode == nullptr) {
		// Next node in SCC.
		causesNextNewSCCIter = false;
		currNode = currNode->nextNode;
	} else {
		// Jump at start of SCC.
		causesNextNewSCCIter = true;
		currNode = currNode->sccRevNode;
	}

	return &value;
}

/**
* @brief Returns @c true if analysis has something that can be returned,
*        otherwise @c false.
*/
bool TraversalAnalysis::hasSomethingToReturn() {
	return currNode != nullptr;
}

/**
* @brief Returns @c true if next returned item by analysis is part of SCC,
*        otherwise @c false.
*/
bool TraversalAnalysis::isNextInSCC() {
	return currNode->isInSCC;
}

/**
* @brief Returns @c true if next item to return will cause new iteration
*        of SCC, otherwise @c false.
*
* Use only if you are sure that you iterates through the items that are
* part of some SCC. To find out it use @c isNextInSCC().
*/
bool TraversalAnalysis::causeNextNewSCCIteration() {
	return causesNextNewSCCIter;
}

/**
* @brief Stops the iterating over items that are in one SCC.
*
* Use only if you are sure that you iterates through the items that are
* part of some SCC. To find out it use @c isNextInSCC().
*
* @par Preconditions
*  - You have to be in SCC.
*/
void TraversalAnalysis::stopIteratingSCC() {
	assert(currNode->isInSCC && "Use only on items that are part of some SCC");
	// Finds last node in SCC.
	while (currNode->sccRevNode == nullptr) {
		currNode = currNode->nextNode;
	}
	// Sets current node to node after SCC.
	currNode = currNode->nextNode;
}

/**
* @brief Creates connection between @a prevNode and @a nextNode in linked list.
*
* Also sets the first node in linked list as head node.
*/
void TraversalAnalysis::solveConnectionWithNextNode(Node *prevNode,
		Node *nextNode) {
	if (prevNode == nullptr) {
		// First node doesn't have predecessor node.
		headNode = nextNode;
	} else {
		// Do a connection.
		prevNode->nextNode = nextNode;
	}
}

/**
* @brief Clears allocated nodes.
*/
void TraversalAnalysis::clear() {
	currNode = headNode;
	// Destroy linked list.
	while (currNode != nullptr) {
		headNode = currNode->nextNode;
		delete currNode;
		currNode = headNode;
	}
}

/**
* @brief Returns created new node for @a val which is in SCC.
*/
TraversalAnalysis::Node *TraversalAnalysis::Node::createNodeInSCC(Value &val) {
	return new Node(val, true);
}

/**
* @brief Returns created new node for @a val which is not in SCC.
*/
TraversalAnalysis::Node *TraversalAnalysis::Node::createNodeNotInSCC(
		Value &val) {
	return new Node(val, false);
}

} // namespace bin2llvmir
} // namespace retdec
