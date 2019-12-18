/**
* @file src/llvmir2hll/graphs/cfg/cfg_traversal.cpp
* @brief Implementation of CFGTraversal.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <stack>
#include <tuple>
#include <unordered_set>

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Generic depth-first iterator.
*/
template <class Graph>
class df_iterator {
private:
	using Node = ShPtr<typename Graph::Node>;

	// Standard typedefs.
	using value_type = Node;
	using reference = value_type&;
	using pointer = value_type*;
	using difference_type = std::ptrdiff_t;
	using iterator_category = std::forward_iterator_tag;

	// The stack nodes consist of the current CFG node, a statement iterator
	// storing the current place in the node's statements, and an iterator
	// storing the current place in the node's successor list.  Statement place
	// is only needed because we may be called with a statement that doesn't
	// point to the beginning.
	using StackNodeType = std::tuple<Node, typename Graph::stmt_iterator, typename Graph::succ_iterator>;
	using ReturnNodeType = std::pair<Node, typename Graph::stmt_iterator>;
	std::stack<StackNodeType> visitStack;
	std::unordered_set<Node> visitedNodes;

private:
	df_iterator(Node node, typename Graph::stmt_iterator stmtIter) {
		// If we don't start at the node beginning, we cannot say this node was
		// visited, because we may need to come back and iterate from its start
		// to the original starting statement.
		if (stmtIter == node->stmt_begin()) {
			visitedNodes.insert(node);
		}
		visitStack.emplace(node, stmtIter, node->succ_begin());
	}

	df_iterator(Node node): df_iterator(node, node->stmt_begin()) {
	}

	df_iterator() = default; // End is when stack is empty.

	void moveToNextNode() {
		// Note that we directly mutate the successor iterators that are
		// on the stack, because we can't pop it until we are done.
		do {
			auto node = std::get<0>(visitStack.top());
			auto &succPlace = std::get<2>(visitStack.top());
			// Now push the next successor on the stack to make it
			// get visited.
			while (succPlace != node->succ_end()) {
				auto succNode((*succPlace)->getDst());
				// This mutates the actual in-stack succ iterator.
				++succPlace;
				// Push this node on the stack to be visited if
				// it hasn't been visited.
				if (visitedNodes.insert(succNode).second) {
					visitStack.emplace(succNode, succNode->stmt_begin(),
						succNode->succ_begin());
					return;
				}
			}
			// Otherwise, we need to pop up a level because we are done
			// completely with the stack node.
			visitStack.pop();
		} while (!visitStack.empty());
	}

public:
	// using pointer = typename super::pointer;

	// Provide static begin and end methods as our public "constructors".
	static df_iterator<Graph> begin(const Node &N) {
		return df_iterator(N);
	}
	static df_iterator<Graph> begin(const Node &N, typename Graph::stmt_iterator stmtIter) {
		return df_iterator(N, stmtIter);
	}

	static df_iterator<Graph> end(const Node &N) { return df_iterator(); }

	bool operator==(const df_iterator &x) const {
		return visitStack == x.visitStack;
	}
	bool operator!=(const df_iterator &x) const {
		return !(*this == x);
	}

	ReturnNodeType operator*() const {
		auto &topNode = visitStack.top();
		return std::make_pair(std::get<0>(topNode), std::get<1>(topNode));
	}

	df_iterator &operator++() { // Preincrement
		moveToNextNode();
		return *this;
	}

	// Skips all children of the current node.  Note that this may cause the
	// iterator to be at end when it is done.
	df_iterator &skipChildren() {
		visitStack.pop();
		return *this;
	}

	df_iterator operator++(int) { // Postincrement
		df_iterator tmp = *this;
		++*this;
		return tmp;
	}
};

} // anonymous namespace

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

	auto retVal = getEndRetVal();
	if (stmtInNode.second != stmtInNode.first->stmt_end()) {
		// It has a successor in the same node, so start traversing from the
		// successor.
		return performTraversalImpl(stmtInNode.first, ++stmtInNode.second);
	} else {
		auto node = stmtInNode.first;
		// It is the last statement in the node, so traverse all node successors.
		// For each outgoing edge...
		for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
			ShPtr<CFG::Node> dstNode((*i)->getDst());
			retVal = combineRetVals(retVal, performTraversalImpl(node, node->stmt_end()));
			if (stopTraversal) {
				break;
			}
		}
	}
	return retVal;
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
* @brief A non-recursive implementation of performTraversal().
*
* @param[in] node Node to be traversed.
* @param[in] stmtIter Iterator to a statement in @a node to be checked.
*
* This function traverses the entire CFG rooted at @a node, starting with the statement
* in @a stmtIter.
*/
bool CFGTraversal::performTraversalImpl(ShPtr<CFG::Node> node,
		CFG::stmt_iterator stmtIter) {
	// Walk the CFG rooted at node in depth first order.
	auto retVal = getEndRetVal();
	for (auto i = df_iterator<CFG>::begin(node, stmtIter), e = df_iterator<CFG>::end(node); i != e; ++i) {
		auto nodePair = *i;
		auto node = nodePair.first;
		auto stmtPlace = nodePair.second;
		auto visitState = visitSingleNode(stmtPlace, node->stmt_end());

		retVal = combineRetVals(retVal, visitState.first);
		if (stopTraversal) {
			break;
		}
		// If we got asked to skip children, do it.
		if (visitState.second) {
			// This may cause us to be at the end of the iterator.
			i.skipChildren();
			if (i == e) {
				break;
			}
		}
	}

	return retVal;
}

/**
* @brief Visit a single node during our traversal, and all the statements in it.
*
* @param[in] stmtIter Iterator to a statement in node to be checked.
* @param[in] endStmt Iterator to last statement in node to be checked.
*
* @return Result of the visit, and whether to skip children of the node.
*/
std::pair<bool, bool> CFGTraversal::visitSingleNode(CFG::stmt_iterator stmtIter,
		CFG::stmt_iterator endStmt) {
	while (stmtIter != endStmt) {
		// We're not at the end of the node, so check the statement under
		// stmtIter.

		if (hasItem(checkedStmts, *stmtIter)) {
			return std::make_pair(getEndRetVal(), false);
		}
		checkedStmts.insert(*stmtIter);

		bool shouldContinue = visitStmt(*stmtIter);
		if (!shouldContinue || stopTraversal) {
			return std::make_pair(getCurrRetVal(), true);
		}

		++stmtIter;
	}
	return std::make_pair(getEndRetVal(), false);
}

/**
* @brief A non-recursive implementation of performReverseTraversal().
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
	while (stmtRIter != node->stmt_rend()) {
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

		++stmtRIter;
	}

	// We have reached the start of the node, so check node's predecessors.
	return traverseNodePredecessors(node);
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
