/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/cfg_node.cpp
* @brief Implementation of CFGNode.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/cfg_node.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new control-flow graph edge.
*
* @param[in] target A target of the currently created edge.
*/
CFGNode::CFGEdge::CFGEdge(ShPtr<CFGNode> target):
	target(target), backEdge(false) {}

/**
* @brief Returns the target of this edge.
*/
ShPtr<CFGNode> CFGNode::CFGEdge::getTarget() const {
	return target;
}

/**
* @brief Returns @c true if this edge is a back-edge.
*/
bool CFGNode::CFGEdge::isBackEdge() const {
	return backEdge;
}

/**
* @brief Sets flag whether this node is a back-edge to value @a isBackEdge.
*/
void CFGNode::CFGEdge::setBackEdge(bool isBackEdge) {
	backEdge = isBackEdge;
}

/**
* @brief Constructs a new control-flow graph node.
*
* @param[in] bb An LLVM basic block to store to this tree node.
* @param[in] body A converted body of this tree node.
*/
CFGNode::CFGNode(llvm::BasicBlock *bb, ShPtr<Statement> body):
	firstBasicBlock(bb), lastBasicBlock(bb), body(body),
	predecessors(), successors(), statementSuccessor() {}

/**
* @brief Returns the first LLVM basic block in sequence which is represented by
*        this node.
*/
llvm::BasicBlock *CFGNode::getFirstBB() const {
	return firstBasicBlock;
}

/**
* @brief Returns the last LLVM basic block in sequence which is represented by
*        this node.
*/
llvm::BasicBlock *CFGNode::getLastBB() const {
	return lastBasicBlock;
}

/**
* @brief Sets @a bb as the last LLVM basic block in sequence which is
*        represented by this node.
*/
void CFGNode::setLastBB(llvm::BasicBlock *bb) {
	lastBasicBlock = bb;
}

/**
* @brief Returns the terminator instruction of stored basic block in this node.
*/
llvm::TerminatorInst *CFGNode::getTerm() const {
	return lastBasicBlock->getTerminator();
}

/**
* @brief Returns a condition of this node if this is conditional branch.
*        Otherwise, returns nullptr.
*/
llvm::Value *CFGNode::getCond() const {
	if (auto branchInst = llvm::dyn_cast<llvm::BranchInst>(getTerm())) {
		if (branchInst->isConditional()) {
			return branchInst->getCondition();
		}
	} else if (auto switchInst = llvm::dyn_cast<llvm::SwitchInst>(getTerm())) {
		return switchInst->getCondition();
	}

	FAIL("Trying to get condition from node '" << lastBasicBlock->getName()
		<< "' which is neither conditional branch nor switch.");
	return nullptr;
}

/**
* @brief Returns the body in BIR of this node.
*/
ShPtr<Statement> CFGNode::getBody() const {
	return body;
}

/**
* @brief Sets a new body @a body to this node.
*
* @par Preconditions
*  - @a body is non-null
*/
void CFGNode::setBody(ShPtr<Statement> body) {
	PRECONDITION_NON_NULL(body);

	this->body = body;
}

/**
* @brief Appends the given statement @a statement to this node's body.
*
* Appended statement @a statement could be also nullptr.
*/
void CFGNode::appendToBody(ShPtr<Statement> statement) {
	body = Statement::mergeStatements(body, statement);
}

/**
* @brief Adds a new successor @a succ to this node.
*
* This method also adds self as predecessor to currently added successor.
*
* @par Preconditions
*  - @a succ is non-null
*/
void CFGNode::addSuccessor(ShPtr<CFGNode> succ) {
	PRECONDITION_NON_NULL(succ);

	successors.push_back(std::make_shared<CFGEdge>(succ));
	succ->predecessors.insert(shared_from_this());
}

/**
* @brief Moves all successors from the given node @a node to this node.
*
* @par Preconditions
*  - @a node is non-null
*/
void CFGNode::moveSuccessorsFrom(const ShPtr<CFGNode> &node) {
	PRECONDITION_NON_NULL(node);

	for (const auto &succ: node->successors) {
		successors.push_back(succ);
		succ->getTarget()->predecessors.insert(shared_from_this());
	}

	deleteSucc(0);
}

/**
* @brief Removes a successor of this node on the index @a i.
*
* Remove means that node will be removed from successors and also back edge
* from successor to current node will be removed.
*
* @par Preconditions
*  - <tt>i < NUM_NODE_SUCC</tt>, where @c NUM_NODE_SUCC is the number of node's
*    successors
*/
void CFGNode::removeSucc(std::size_t i) {
	PRECONDITION(i < getSuccNum(), "i `" << i << "`" << " is greater "
		"than node's successors (`" << getSuccNum() << "`)");

	auto succ = successors[i]->getTarget();

	// If currently removed successor is also the statement successor,
	// do not remove it from successor's predecessors.
	if (statementSuccessor != succ) {
		succ->predecessors.erase(shared_from_this());
	}

	successors.erase(successors.begin() + i);
}

/**
* @brief Deletes a successor of this node on the index @a i.
*
* Delete means that deleted node will be removed from the tree and all edges
* to this node will be removed.
*
* @par Preconditions
*  - <tt>i < NUM_NODE_SUCC</tt>, where @c NUM_NODE_SUCC is the number of node's
*    successors
*/
void CFGNode::deleteSucc(std::size_t i) {
	PRECONDITION(i < getSuccNum(), "i `" << i << "`" << " is greater "
		"than node's successors (`" << getSuccNum() << "`)");

	auto succ = successors[i]->getTarget();

	while (!succ->successors.empty()) {
		succ->removeSucc(0);
	}

	removeSucc(i);
}

/**
* @brief Deletes all successors of this node.
*/
void CFGNode::deleteSuccessors() {
	while (!successors.empty()) {
		deleteSucc(0);
	}
}

/**
* @brief Returns a number of this node successors.
*/
std::size_t CFGNode::getPredsNum() const {
	return predecessors.size();
}

/**
* @brief Returns a number of this node successors.
*/
std::size_t CFGNode::getSuccNum() const {
	return successors.size();
}

/**
* @brief Returns a set of predecessors of this node.
*/
CFGNode::CFGNodeSet CFGNode::getPredecessors() {
	return predecessors;
}

/**
* @brief Returns a vector of successors of this node.
*/
CFGNode::CFGNodeVector CFGNode::getSuccessors() {
	CFGNodeVector succs;
	for (const auto &elem: successors) {
		succs.push_back(elem->getTarget());
	}

	return succs;
}

/**
* @brief Returns a successor of this node on the index @a i.
*
* @par Preconditions
*  - <tt>i < NUM_NODE_SUCC</tt>, where @c NUM_NODE_SUCC is the number of node's
*    successors
*/
ShPtr<CFGNode> CFGNode::getSucc(std::size_t i) const {
	PRECONDITION(i < getSuccNum(), "i `" << i << "`" << " is greater "
		"than node's successors (`" << getSuccNum() << "`)");

	return successors[i]->getTarget();
}

/**
* @brief Returns a successor of this node on the index @a i. If this node does
*        not have a successor on the index @a i, it returns nullptr.
*/
ShPtr<CFGNode> CFGNode::getSuccOrNull(std::size_t i) const {
	if (i >= getSuccNum()) {
		return nullptr;
	}

	return successors[i]->getTarget();
}

/**
* @brief Determines whether the given node @a node is this node's successor.
*
* @par Preconditions
*  - @a node is non-null
*/
bool CFGNode::hasSuccessor(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	for (const auto &succ: successors) {
		if (succ->getTarget() == node) {
			return true;
		}
	}

	return false;
}

/**
* @brief Sets flag that this node's succ @a node is a back-edge.
*/
void CFGNode::markAsBackEdge(const ShPtr<CFGNode> &node) {
	for (auto &succ: successors) {
		if (succ->getTarget() == node) {
			succ->setBackEdge();
			return;
		}
	}
}

/**
* @brief Returns @c true if this node's succ @a node is a back-edge.
*/
bool CFGNode::isBackEdge(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	for (const auto &succ: successors) {
		if (succ->getTarget() == node) {
			return succ->isBackEdge();
		}
	}

	return false;
}

/**
* @brief Determines whether this node has a statement successor.
*/
bool CFGNode::hasStatementSuccessor() const {
	return statementSuccessor != nullptr;
}

/**
* @brief Returns the statement successor.
*/
ShPtr<CFGNode> CFGNode::getStatementSuccessor() const {
	return statementSuccessor;
}

/**
* @brief Sets @a succ as a new statement successor.
*/
void CFGNode::setStatementSuccessor(ShPtr<CFGNode> succ) {
	removeStatementSuccessor();

	if (succ) {
		statementSuccessor = succ;
		succ->predecessors.insert(shared_from_this());
	}
}

/**
* @brief Removes statement successor if exists.
*/
void CFGNode::removeStatementSuccessor() {
	if (statementSuccessor) {
		// If currently removed statement successor is also a successor,
		// do not remove it from successor's predecessors.
		if (!hasSuccessor(statementSuccessor)) {
			statementSuccessor->predecessors.erase(shared_from_this());
		}

		statementSuccessor = nullptr;
	}
}

/**
* @brief Returns the label of first basic block in this node.
*/
std::string CFGNode::getName() const {
	if (!firstBasicBlock->hasName()) {
		return "<unnamed>";
	}

	return firstBasicBlock->getName();
}

/**
* @brief Emits this node's name and its successors and predecessors to the
*        standard error output.
*
* Only for debugging purposes.
*/
void CFGNode::debugPrint() const {
	std::string succStr;
	for (const auto &succ: successors) {
		if (!succStr.empty()) {
			succStr += ", ";
		}

		succStr += succ->getTarget()->getName();
	}

	std::string predStr;
	for (const auto &pred: predecessors) {
		if (!predStr.empty()) {
			predStr += ", ";
		}

		predStr += pred->getName();
	}

	llvm::errs() << "Node " << getName() << ": successors = [" << succStr
		<< "], predecessors = [" << predStr << "]\n";
}

} // namespace llvmir2hll
} // namespace retdec
