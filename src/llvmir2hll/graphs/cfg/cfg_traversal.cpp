/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversal.cpp
* @brief Implementation of CFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new traverser.
*
* @param[in] cfg CFG that should be traversed.
* @param[in] defaultCurrRetVal Default value of @c currRetVal.
*
* @par Preconditions
*  - @c cfg is non-null
*/
CFGTraversal::CFGTraversal(ShPtr<CFG> cfg, bool defaultCurrRetVal):
		cfg(cfg), currRetVal(defaultCurrRetVal), stopTraversal(false) {
	PRECONDITION_NON_NULL(cfg);
}

/**
* @brief Destructs the traverser.
*/
CFGTraversal::~CFGTraversal() {}

/**
* @brief Performs a traversal of the current CFG, starting at @a startStmt.
*
* @return Result of the traversal (its meaning may vary from subclass to
*         subclass).
*
* @par Preconditions
*   - @a startStmt is non-null and it is not an empty statement (recall that a
*     CFG doesn't contain empty statements)
*/
bool CFGTraversal::performTraversal(ShPtr<Statement> startStmt) {
	PRECONDITION_NON_NULL(startStmt);
	PRECONDITION(!isa<EmptyStmt>(startStmt),
		"a CFG traversal cannot start from an empty statement");

	// Initialization.
	stopTraversal = false;

	CFG::StmtInNode startStmtInNode(cfg->getNodeForStmt(startStmt));
	ASSERT_MSG(startStmtInNode.first,
		"the statement `" << startStmt << "` is not in the CFG");
	return performTraversalImpl(startStmtInNode.first, startStmtInNode.second);
}

/**
* @brief Performs a traversal of the current CFG, starting at the
*        successor(s) of @a stmt.
*
* @return Result of the traversal (its meaning may vary from subclass to
*         subclass).
*
* @par Preconditions
*   - @a startStmt is non-null and it is not an empty statement (recall that a
*     CFG doesn't contain empty statements)
*/
bool CFGTraversal::performTraversalFromSuccessors(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION(!isa<EmptyStmt>(stmt),
		"a CFG traversal cannot start from an empty statement");

	// Initialization.
	stopTraversal = false;

	CFG::StmtInNode stmtInNode(cfg->getNodeForStmt(stmt));
	ASSERT_MSG(stmtInNode.first,
		"the statement `" << stmt << "` is not in the CFG");

	if (stmtInNode.second != stmtInNode.first->stmt_end()) {
		// It has a successor in the same node, so start traversing from the
		// successor.
		return performTraversalImpl(stmtInNode.first, ++stmtInNode.second);
	}
	// It is the last statement in the node, so traverse all node successors.
	return traverseNodeSuccessors(stmtInNode.first);
}

/**
* @brief Performs a reverse traversal of the current CFG, starting at @a startStmt.
*
* @return Result of the traversal (its meaning may vary from subclass to
*         subclass).
*
* @par Preconditions
*   - @a startStmt is non-null and it is not an empty statement (recall that a
*     CFG doesn't contain empty statements)
*/
bool CFGTraversal::performReverseTraversal(ShPtr<Statement> startStmt) {
	PRECONDITION_NON_NULL(startStmt);
	PRECONDITION(!isa<EmptyStmt>(startStmt),
		"a CFG traversal cannot start from an empty statement");

	// Initialization.
	stopTraversal = false;

	CFG::StmtInNode startStmtInNode(cfg->getNodeForStmt(startStmt));
	ASSERT_MSG(startStmtInNode.first,
		"the statement `" << startStmt << "` is not in the CFG");
	return performReverseTraversalImpl(startStmtInNode.first,
		cfg->getReverseIteratorFromIterator(startStmtInNode.second));
}

/**
* @brief Performs a reverse traversal of the current CFG, starting at the
*        predecessor(s) of @a stmt.
*
* @return Result of the traversal (its meaning may vary from subclass to
*         subclass).
*
* @par Preconditions
*   - @a startStmt is non-null and it is not an empty statement (recall that a
*     CFG doesn't contain empty statements)
*/
bool CFGTraversal::performReverseTraversalFromPredecessors(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION(!isa<EmptyStmt>(stmt),
		"a CFG traversal cannot start from an empty statement");

	// Initialization.
	stopTraversal = false;

	CFG::StmtInNode stmtInNode(cfg->getNodeForStmt(stmt));
	ASSERT_MSG(stmtInNode.first,
		"the statement `" << stmt << "` is not in the CFG");

	if (stmtInNode.second != stmtInNode.first->stmt_begin()) {
		// It has a predecessor in the same node, so start traversing from the
		// predecessor.
		return performReverseTraversalImpl(stmtInNode.first,
			++cfg->getReverseIteratorFromIterator(stmtInNode.second));
	}
	// It is the first statement in the node, so traverse all node predecessors.
	return traverseNodePredecessors(stmtInNode.first);
}

/**
* @brief Returns the value that should be returned as the result of
*        visiting a statement.
*
* This function can be called only after calling visitStmt().
*/
bool CFGTraversal::getCurrRetVal() const {
	return currRetVal;
}

/**
* @brief A recursive implementation of performTraversal().
*
* @param[in] node Node to be traversed.
* @param[in] stmtIter Iterator to a statement in @a node to be checked.
*
* If @a stmtIter equals @c node->stmt_end(), the function traverses all
* successors of @a node.
*/
bool CFGTraversal::performTraversalImpl(ShPtr<CFG::Node> node,
		CFG::stmt_iterator stmtIter) {
	if (stmtIter != node->stmt_end()) {
		// We're not at the end of the node, so check the statement under
		// stmtIter.

		if (hasItem(checkedStmts, *stmtIter)) {
			return getEndRetVal();
		}
		checkedStmts.insert(*stmtIter);

		bool shouldContinue = visitStmt(*stmtIter);
		if (!shouldContinue || stopTraversal) {
			return getCurrRetVal();
		}

		return performTraversalImpl(node, ++stmtIter);
	}

	// We have reached the end of the node, so check node's successors.
	return traverseNodeSuccessors(node);
}

/**
* @brief A recursive implementation of performReverseTraversal().
*
* @param[in] node Node to be traversed.
* @param[in] stmtRIter Reverse iterator to a statement in @a node to be
*                      checked.
*
* If @a stmtIter equals @c node->stmt_rend(), the function traverses all
* predecessors of @a node.
*/
bool CFGTraversal::performReverseTraversalImpl(ShPtr<CFG::Node> node,
		CFG::stmt_reverse_iterator stmtRIter) {

	if (stmtRIter != node->stmt_rend()) {
		// We're not at the start of the node, so check the statement under
		// stmtRIter.

		if (hasItem(checkedStmts, *stmtRIter)) {
			return getEndRetVal();
		}
		checkedStmts.insert(*stmtRIter);

		bool shouldContinue = visitStmt(*stmtRIter);
		if (!shouldContinue || stopTraversal) {
			return getCurrRetVal();
		}

		return performReverseTraversalImpl(node, ++stmtRIter);
	}

	// We have reached the start of the node, so check node's predecessors.
	return traverseNodePredecessors(node);
}

/**
* @brief Traverses all the successors of @a node.
*
* @return Result of the traversal, just like performTraversal().
*
* This function is meant to be called within functions traversing a CFG.
*/
bool CFGTraversal::traverseNodeSuccessors(ShPtr<CFG::Node> node) {
	bool retVal = getEndRetVal();
	// For each outgoing edge...
	for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
		ShPtr<CFG::Node> dstNode((*i)->getDst());
		retVal = combineRetVals(retVal, performTraversalImpl(dstNode,
			dstNode->stmt_begin()));
		if (stopTraversal) {
			break;
		}
	}
	return retVal;
}

/**
* @brief Traverses all the predecessors of @a node.
*
* @return Result of the traversal, just like performReverseTraversal().
*
* This function is meant to be called within functions traversing a CFG in
* reverse.
*/
bool CFGTraversal::traverseNodePredecessors(ShPtr<CFG::Node> node) {
	bool retVal = getEndRetVal();
	// For each ingoing edge...
	for (auto i = node->pred_begin(), e = node->pred_end(); i != e; ++i) {
		ShPtr<CFG::Node> srcNode((*i)->getSrc());
		retVal = combineRetVals(retVal, performReverseTraversalImpl(srcNode,
			srcNode->stmt_rbegin()));
		if (stopTraversal) {
			break;
		}
	}
	return retVal;
}

} // namespace llvmir2hll
} // namespace retdec
