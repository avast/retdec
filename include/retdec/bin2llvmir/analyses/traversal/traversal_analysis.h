/**
* @file include/retdec/bin2llvmir/analyses/traversal/traversal_analysis.h
* @brief Base class for traversal analyses.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_TRAVERSAL_TRAVERSAL_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_TRAVERSAL_TRAVERSAL_ANALYSIS_H

#include <llvm/IR/Value.h>

namespace retdec {
namespace bin2llvmir {

/**
* @brief Base class for traversal analyses.
*
* This class contains shared implementation for traversal analyses so you can't
* create instance of this class. You have to use specific traversal.
*/
class TraversalAnalysis {
public:
	bool hasSomethingToReturn();
	bool isNextInSCC();
	bool causeNextNewSCCIteration();
	void stopIteratingSCC();

protected:
	/// One node in linked list.
	struct Node {
		static Node *createNodeInSCC(llvm::Value &val);
		static Node *createNodeNotInSCC(llvm::Value &val);

		/// Value of node.
		llvm::Value &value;

		/// If this node represents one node of SCC.
		bool isInSCC;

		/// Next node.
		Node *nextNode;

		/// First node in SCC.
		Node *sccRevNode;

	private:
		Node(llvm::Value &value, bool isInSCC): value(value), isInSCC(isInSCC),
			nextNode(nullptr), sccRevNode(nullptr) {}
	};

protected:
	TraversalAnalysis();
	~TraversalAnalysis();

	llvm::Value *getNextVal();
	llvm::Value *getNextValInSCC();
	void solveConnectionWithNextNode(Node *prevNode, Node *nextNode);
	void clear();

	void print();

protected:
	/// The first node in linked list.
	Node *headNode;

	/// Current node.
	Node *currNode;

	/// Signalizes if next basic block causes new SCC iteration.
	bool causesNextNewSCCIter;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
