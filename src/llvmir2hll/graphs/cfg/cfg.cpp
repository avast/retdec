/**
* @file src/llvmir2hll/graphs/cfg/cfg.cpp
* @brief Implementation of CFG.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <set>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"

using retdec::utils::hasItem;
using retdec::utils::removeItem;
using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Set of nodes.
using NodeSet = std::set<ShPtr<CFG::Node>>;

} // anonymous namespace

/**
* @brief Constructs a new node.
*/
CFG::Node::Node() {}

/**
* @brief Constructs a new node with the selected @a label.
*/
CFG::Node::Node(const std::string &label): label(label) {}

/**
* @brief Destructs the node.
*/
CFG::Node::~Node() {}

/**
* @brief Returns the node's label.
*
* If the node has no label, the label or metadata of its first statement is
* returned. Otherwise, if the node has no statements, the empty string is
* returned.
*/
std::string CFG::Node::getLabel() const {
	if (!label.empty()) {
		return label;
	}

	if (!stmts.empty()) {
		auto firstStmt = stmts.front();

		// Label?
		if (firstStmt->hasLabel()) {
			return firstStmt->getLabel();
		}

		// Metadata?
		auto metadata = firstStmt->getMetadata();
		if (!metadata.empty()) {
			return metadata;
		}
	}

	return "";
}

/**
* @brief Returns @c true if the node has some statements, @c false otherwise.
*/
bool CFG::Node::hasStmts() const {
	return !stmts.empty();
}

/**
* @brief Returns the number of statements in the node.
*/
std::size_t CFG::Node::getNumberOfStmts() const {
	return stmts.size();
}

/**
* @brief Adds @a stmt to the statements in the node.
*
* @par Preconditions
*   - @a stmt is non-null
*/
void CFG::Node::addStmt(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	stmts.push_back(stmt);
}

/**
* @brief Replaces @a stmt with @a stmts.
*
* If @a stmt does not exist in the node, this function does nothing.
*
* @par Preconditions
*   - both @a stmt and @a stmts are non-null
*/
void CFG::Node::replaceStmt(ShPtr<Statement> stmt, const StmtVector &stmts) {
	this->stmts.insert(
		std::find(this->stmts.begin(), this->stmts.end(), stmt),
		stmts.begin(),
		stmts.end()
	);
	removeStmt(stmt);
}

/**
* @brief Removes the given statement from the node.
*
* If there is no such statement in the node, this function does nothing.
*
* @par Preconditions
*   - @a stmt is non-null
*/
void CFG::Node::removeStmt(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	removeItem(stmts, stmt);
}

/**
* @brief Returns an iterator to the first statement in the basic block.
*/
CFG::stmt_iterator CFG::Node::stmt_begin() const {
	return stmts.begin();
}

/**
* @brief Returns an iterator past the last statement in the basic block.
*/
CFG::stmt_iterator CFG::Node::stmt_end() const {
	return stmts.end();
}

/**
* @brief Returns a constant reverse iterator to the last statement in the basic
*        block.
*/
CFG::stmt_reverse_iterator CFG::Node::stmt_rbegin() const {
	return stmts.rbegin();
}

/**
* @brief Returns a constant reverse iterator before the first statement in the
*        basic block.
*/
CFG::stmt_reverse_iterator CFG::Node::stmt_rend() const {
	return stmts.rend();
}

/**
* @brief Returns @c true if the node has some successors, @c false otherwise.
*/
bool CFG::Node::hasSuccs() const {
	return !succs.empty();
}

/**
* @brief Returns @c true if the node has the given successor, @c false
*        otherwise.
*
* @par Preconditions
*   - @a edge is non-null
*/
bool CFG::Node::hasSucc(ShPtr<Edge> edge) const {
	PRECONDITION_NON_NULL(edge);

	return hasItem(succs, edge);
}

/**
* @brief Returns the number of successors.
*/
std::size_t CFG::Node::getNumberOfSuccs() const {
	return succs.size();
}

/**
* @brief Adds the given successor to the node.
*
* @par Preconditions
*   - @a succ is non-null
*/
void CFG::Node::addSucc(ShPtr<Edge> succ) {
	PRECONDITION_NON_NULL(succ);

	succs.push_back(succ);
}

/**
* @brief Returns the first successor of the node.
*
* If there are no successors, the null pointer is returned.
*/
ShPtr<CFG::Edge> CFG::Node::getFirstSucc() const {
	return !succs.empty() ? succs.front() : ShPtr<CFG::Edge>();
}

/**
* @brief Removes the given successor from the node.
*
* If the given successor doesn't exist in the node, this function does nothing.
*
* @par Preconditions
*   - @a succ is non-null
*/
void CFG::Node::removeSucc(ShPtr<Edge> succ) {
	PRECONDITION_NON_NULL(succ);

	removeItem(succs, succ);
}

/**
* @brief Returns an iterator to the first edge leaving the node.
*/
CFG::succ_iterator CFG::Node::succ_begin() const {
	return succs.begin();
}

/**
* @brief Returns an iterator past the last edge leaving the node.
*/
CFG::succ_iterator CFG::Node::succ_end() const {
	return succs.end();
}

/**
* @brief Returns @c true if the node has some predecessors, @c false otherwise.
*/
bool CFG::Node::hasPreds() const {
	return !preds.empty();
}

/**
* @brief Returns @c true if the node has the given predecessor, @c false
*        otherwise.
*
* @par Preconditions
*   - @a edge is non-null
*/
bool CFG::Node::hasPred(ShPtr<Edge> edge) const {
	PRECONDITION_NON_NULL(edge);

	return hasItem(preds, edge);
}

/**
* @brief Returns the number of predecessors.
*/
std::size_t CFG::Node::getNumberOfPreds() const {
	return preds.size();
}

/**
* @brief Adds the given predecessor to the node.
*
* @par Preconditions
*   - @a pred is non-null
*/
void CFG::Node::addPred(ShPtr<Edge> pred) {
	PRECONDITION_NON_NULL(pred);

	preds.push_back(pred);
}

/**
* @brief Removes the given predecessor from the node.
*
* If the given predecessor doesn't exist in the node, this function does nothing.
*
* @par Preconditions
*   - @a pred is non-null
*/
void CFG::Node::removePred(ShPtr<Edge> pred) {
	PRECONDITION_NON_NULL(pred);

	removeItem(preds, pred);
}

/**
* @brief Returns an iterator to the first edge entering the node.
*/
CFG::pred_iterator CFG::Node::pred_begin() const {
	return preds.begin();
}

/**
* @brief Returns an iterator past the last edge entering the node.
*/
CFG::pred_iterator CFG::Node::pred_end() const {
	return preds.end();
}

/**
* @brief Constructs a new edge <tt>src -> dst</tt>, optionally labelled by
*        @a label.
*
* @param[in] src Source node.
* @param[in] dst Destination node.
* @param[in] label Optional edge label.
*/
CFG::Edge::Edge(ShPtr<Node> src, ShPtr<Node> dst, ShPtr<Expression> label):
	src(src), label(label), dst(dst) {}

/**
* @brief Destructs the edge.
*/
CFG::Edge::~Edge() {}

/**
* @brief Returns the source node of the edge.
*/
ShPtr<CFG::Node> CFG::Edge::getSrc() const {
	return src;
}

/**
* @brief Returns the edge's label.
*
* The returned label may be null.
*/
ShPtr<Expression> CFG::Edge::getLabel() const {
	return label;
}

/**
* @brief Returns the destination node of the edge.
*/
ShPtr<CFG::Node> CFG::Edge::getDst() const {
	return dst;
}

/**
* @brief Constructs a new CFG.
*
* @param[in] func The CFG will correspond to this function.
*/
CFG::CFG(ShPtr<Function> func): correspondingFunction(func) {}

/**
* @brief Destructs the CFG.
*/
CFG::~CFG() {}

/**
* @brief Returns the function which corresponds to the CFG.
*
* In other words, it returns the function from which this CFG was created.
*/
ShPtr<Function> CFG::getCorrespondingFunction() const {
	return correspondingFunction;
}

/**
* @brief Adds the given entry node to the CFG.
*
* @par Preconditions
*   - @a node is non-null
*/
void CFG::addEntryNode(ShPtr<Node> node) {
	PRECONDITION_NON_NULL(node);

	addNode(node);
	entryNode = node;
}

/**
* @brief Adds the given entry node to the CFG.
*
* @par Preconditions
*   - @a node is non-null
*/
void CFG::addExitNode(ShPtr<Node> node) {
	PRECONDITION_NON_NULL(node);

	addNode(node);
	exitNode = node;
}

/**
* @brief Returns the entry node of the CFG.
*/
ShPtr<CFG::Node> CFG::getEntryNode() const {
	return entryNode;
}

/**
* @brief Returns the exit node of the CFG.
*/
ShPtr<CFG::Node> CFG::getExitNode() const {
	return exitNode;
}

/**
* @brief Returns @c true if the given statement exists in the CFG, @c false
*        otherwise.
*
* @par Preconditions
*   - @a stmt is non-null
*/
bool CFG::stmtExistsInCFG(ShPtr<Statement> stmt) const {
	PRECONDITION_NON_NULL(stmt);

	return stmtNodeMapping.find(stmt) != stmtNodeMapping.end();
}

/**
* @brief Returns the node and position of the given statement in the CFG.
*
* If @a stmt doesn't exist in the CFG, the first component of the returned pair
* is the null pointer. The second component is then (obviously) invalid.
*
* @par Preconditions
*   - @a stmt is non-null
*/
CFG::StmtInNode CFG::getNodeForStmt(ShPtr<Statement> stmt) const {
	PRECONDITION_NON_NULL(stmt);

	// Get the node.
	auto nodeForStmtIter = stmtNodeMapping.find(stmt);
	if (nodeForStmtIter == stmtNodeMapping.end()) {
		// The statement doesn't exist in the CFG.
		return StmtInNode(ShPtr<Node>(), exitNode->stmt_end());
	}
	ShPtr<Node> nodeForStmt(nodeForStmtIter->second);

	// Get the position of the statement within the found node.
	auto stmtPos = std::find(nodeForStmt->stmt_begin(),
		nodeForStmt->stmt_end(), stmt);
	ASSERT_MSG(stmtPos != nodeForStmt->stmt_end(),
		"the statement `" << stmt << "` doesn't exist in the found node.");

	return StmtInNode(nodeForStmt, stmtPos);
}

/**
* @brief Returns @c true if the given statement exists in the CFG, @c false
*        otherwise.
*
* @par Preconditions
*   - @a stmt is non-null
*/
bool CFG::hasNodeForStmt(ShPtr<Statement> stmt) const {
	PRECONDITION_NON_NULL(stmt);

	return getNodeForStmt(stmt).first != nullptr;
}

/**
* @brief Returns a reverse iterator for the given iterator @a i.
*
* @par Preconditions
*  - @a i can be accessed, i.e. it is not a past-end iterator
*/
CFG::stmt_reverse_iterator CFG::getReverseIteratorFromIterator(stmt_iterator i) {
	// Get a node corresponding to the statement under i.
	auto stmtInNode = getNodeForStmt(*i);

	// Start at the end of the node and keep reverse-iterating over it until
	// the statement under i is found.
	auto ri = stmtInNode.first->stmt_rbegin();
	while (*ri != *i) {
		++ri;
	}
	return ri;
}

/**
* @brief Returns the number of nodes in the CFG.
*
* Entry and exit nodes are also included.
*/
std::size_t CFG::getNumberOfNodes() const {
	return nodes.size();
}

/**
* @brief Splits the CFG so that each node contains a single statement.
*
* Nodes for the empty statement are not created.
*/
void CFG::splitNodes() {
	// Since splitNode() may add new nodes, we need to iterate over a copy of
	// the nodes.
	for (auto node : NodeVector(nodes)) {
		splitNode(node);
	}
}

/**
* @brief Removes the given statement from the given node.
*
* If there either is no such node or @a stmt is not in the node, this function
* does nothing.
*
* @par Preconditions
*  - both @a stmt and @a node are non-null
*/
void CFG::removeStmtFromNode(ShPtr<Statement> stmt, ShPtr<CFG::Node> node) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(node);

	auto stmtInNode = getNodeForStmt(stmt);
	if (!stmtInNode.first) {
		return;
	}

	stmtInNode.first->removeStmt(stmt);
	stmtNodeMapping.erase(stmt);
}

/**
* @brief Removes @a stmt from the CFG.
*
* @param[in] stmt Statement to be removed.
*
* If @a stmt doesn't exist in the CFG, this function does nothing.
*
* @par Preconditions
*  - @a stmt is non-null
*/
void CFG::removeStmt(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	// If stmt doesn't exist in the CFG, do nothing.
	auto nodeForStmt = getNodeForStmt(stmt).first;
	if (!nodeForStmt) {
		return;
	}

	// Remove the statement from its node.
	removeStmtFromNode(stmt, nodeForStmt);

	// If the node after the removal still contains some statements, we're
	// done.
	if (nodeForStmt->hasStmts()) {
		return;
	}

	//
	// The node in which stmt is contained just this statement. Therefore, we
	// may remove this node completely since it is empty now.
	//

	// Skip this action if the node is the entry node of the CFG. Otherwise,
	// the resulting CFG might be invalid. Notice that we don't have to check
	// whether it is an exit node since exit nodes never contain a statement.
	if (getEntryNode() == nodeForStmt) {
		return;
	}

	// If there is more than successor, do not remove the node.
	// TODO What if there is more than one successor? Can this happen? How to
	//      handle it? CFG::removeNode() requires the node to have at most one
	//      successor.
	if (nodeForStmt->getNumberOfSuccs() > 1) {
		return;
	}

	removeNode(nodeForStmt);
}

/**
* @brief Replaces @a stmt with @a stmts in the CFG.
*
* @param[in] stmt Statement to be replaced.
* @param[in] stmts Statements that will replace @a stmt.
*
* If @a stmt doesn't exist in the CFG, this function does nothing.
*
* @par Preconditions
*  - @a stmt are non-null
*/
void CFG::replaceStmt(ShPtr<Statement> stmt, const StmtVector &stmts) {
	PRECONDITION_NON_NULL(stmt);

	// If stmt doesn't exist in the CFG, do nothing.
	auto nodeForStmt = getNodeForStmt(stmt).first;
	if (!nodeForStmt) {
		return;
	}

	// If there are no statements with which we should replace stmt,
	// we can use removeStmt().
	if (stmts.empty()) {
		removeStmt(stmt);
		return;
	}

	// Update the statement -> node mapping.
	stmtNodeMapping.erase(stmt);
	for (auto stmt : stmts) {
		stmtNodeMapping[stmt] = nodeForStmt;
	}

	// Replace the statement with the new statements.
	nodeForStmt->replaceStmt(stmt, stmts);
}

/**
* @brief Returns unreachable nodes.
*
* An <em>unreachable node</em> is a node that cannot be reached by traversing
* the graph from the entry node by following the direction of edges.
*
* For example, in the CFG below
* @code
*   Entry
*  /  |  \
* A   B  C    F-+
* |           | |
* D     E     G-+
*  \
*   Exit
* @endcode
* the unreachable nodes are @c E, @c F, and @c G.
*
* In some cases, the exit node can be unreachable as well. For example, this
* may happen for a CFG of the following function:
* @code
* void func() {
*    while (true) {}
* }
* @endcode
*/
CFG::NodeVector CFG::getUnreachableNodes() const {
	// We perform a traversal over the CFG, starting at the entry node. All
	// nodes that are not visited during the traversal are unreachable.
	NodeVector nodesToVisit{entryNode};
	NodeSet visitedNodes;
	while (!nodesToVisit.empty()) {
		// Get and remove the first node to be visited.
		auto node = nodesToVisit.front();
		nodesToVisit.erase(nodesToVisit.begin());

		if (hasItem(visitedNodes, node)) {
			continue;
		}
		visitedNodes.insert(node);

		// Schedule a visit for all successors.
		for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
			nodesToVisit.push_back((*i)->getDst());
		}
	}

	// Compute the unreachable nodes.
	NodeVector unreachableNodes;
	for (auto node : nodes) {
		if (!hasItem(visitedNodes, node)) {
			unreachableNodes.push_back(node);
		}
	}
	return unreachableNodes;
}

/**
* @brief Returns the last statement in the given @a node.
*/
ShPtr<Statement> CFG::getLastStmtInNode(ShPtr<Node> node) {
	stmt_iterator lastStmtIter;
	for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
		lastStmtIter = i;
	}
	return *lastStmtIter;
}

/**
* @brief Returns an iterator to the first node in the CFG.
*/
CFG::node_iterator CFG::node_begin() const {
	return nodes.begin();
}

/**
* @brief Returns an iterator past the last node in the CFG.
*/
CFG::node_iterator CFG::node_end() const {
	return nodes.end();
}

/**
* @brief Returns an iterator to the first edge in the CFG.
*/
CFG::edge_iterator CFG::edge_begin() const {
	return edges.begin();
}

/**
* @brief Returns an iterator past the last edge in the CFG.
*/
CFG::edge_iterator CFG::edge_end() const {
	return edges.end();
}

/**
* @brief Adds a new node to the CFG.
*
* @param[in] label Optional label of the node.
*
* @return The added node.
*/
ShPtr<CFG::Node> CFG::addNode(const std::string &label) {
	auto node = std::make_shared<Node>(label);
	addNode(node);
	return node;
}

/**
* @brief Adds the given node to the CFG.
*/
void CFG::addNode(ShPtr<Node> node) {
	nodes.push_back(node);
}

/**
* @brief Adds a new edge to the CFG.
*
* @param[in] src Source node.
* @param[in] dst Destination node.
* @param[in] label Optional edge label.
*
* @return The added edge.
*
* This function properly updates @c src->succs and @c preds->dst.
*
* @par Preconditions
*  - @a src and @a dst are non-null
*/
ShPtr<CFG::Edge> CFG::addEdge(ShPtr<Node> src, ShPtr<Node> dst,
		ShPtr<Expression> label) {
	PRECONDITION_NON_NULL(src);
	PRECONDITION_NON_NULL(dst);

	auto edge = std::make_shared<CFG::Edge>(src, dst, label);
	edges.push_back(edge);
	src->addSucc(edge);
	dst->addPred(edge);
	return edge;
}

/**
* @brief Removes the selected node from the CFG.
*
* The following actions are done:
*  - If the node has a single successor, all ingoing edges into the node are
*    redirected to this successor. Otherwise, all ingoing edges are removed.
*  - All outgoing edges from the node are removed.
*  - The node is removed from the CFG.
*
* If the node doesn't exist, this function does nothing.
*
* This function may invalidate the existing node iterators.
*
* @par Preconditions
*  - @a node is non-null
*  - @a node is not the entry or the exit node
*/
void CFG::removeNode(ShPtr<Node> node) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(node != entryNode,
		"Trying to remove the entry node.");
	PRECONDITION(node != exitNode,
		"Trying to remove the exit node.");

	if (!hasItem(nodes, node)) {
		// The node doesn't exist.
		return;
	}

	// If the node has a single successor, redirect all ingoing edges to this
	// successor. Otherwise, remove all edges (predecessors and successors).
	if (node->getNumberOfSuccs() == 1) {
		auto succ = node->getFirstSucc()->getDst();

		// Remove the original successor.
		removeEdge(node->getFirstSucc());

		// Redirect all edges from the node's predecessors to the node's successor;
		// otherwise, if the node doesn't have a successor, remove these edges.
		// For every predecessor...
		EdgeVector nodePreds(node->pred_begin(), node->pred_end());
		for (auto pred : nodePreds) {
			// We have to also check that the node differs from its successor;
			// otherwise, if node == succ, we would keep the edges to the node we
			// are going to remove. As a result, there would be edges to a
			// non-existing node.
			if (succ && node != succ) {
				addEdge(pred->getSrc(), succ, pred->getLabel());
			}
			removeEdge(pred);
		}
	} else {
		// The node has either zero or more than one successor. Remove all
		// edges (predecessors and successors).
		EdgeVector nodePreds(node->pred_begin(), node->pred_end());
		for (auto pred : nodePreds) {
			removeEdge(pred);
		}
		EdgeVector nodeSuccs(node->succ_begin(), node->succ_end());
		for (auto succ : nodeSuccs) {
			removeEdge(succ);
		}
	}

	// Remove all statements in the node from the statement -> node mapping to
	// prevent getting invalid information from getNodeForStmt().
	for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
		stmtNodeMapping.erase(*i);
	}

	// Remove the node itself. This may invalidate existing node iterators.
	removeItem(nodes, node);
}

/**
* @brief Removes the selected edge from the CFG.
*
* If the selected edge doesn't exist, this function does nothing.
*
* @par Preconditions
*  - @a edge is non-null
*/
void CFG::removeEdge(ShPtr<Edge> edge) {
	PRECONDITION_NON_NULL(edge);

	removeItem(edges, edge);
	edge->getSrc()->removeSucc(edge);
	edge->getDst()->removePred(edge);
}

/**
* @brief Splits the given node into several nodes, each containing a single
*        statement.
*
* Nodes for the empty statement are not created.
*/
void CFG::splitNode(ShPtr<Node> node) {
	// If there is only a single statement in node, we're done.
	if (node->getNumberOfStmts() == 1) {
		return;
	}

	//
	// First, create a new node for each statement in the node.
	//

	// For each statement in the node (except the first one which we can skip
	// since it already has an associated node)...
	auto lastNode = node;
	ShPtr<Edge> edgeFromNodeToSecondNode;
	auto secondStmtIter = ++node->stmt_begin();
	for (auto i = secondStmtIter, e = node->stmt_end(); i != e; ++i) {
		// Skip empty statements.
		if (isa<EmptyStmt>(*i)) {
			continue;
		}

		auto newNode = addNode();
		newNode->addStmt(*i);
		stmtNodeMapping[*i] = newNode;

		auto newEdge = addEdge(lastNode, newNode);
		if (!edgeFromNodeToSecondNode) {
			edgeFromNodeToSecondNode = newEdge;
		}

		lastNode = newNode;
	}

	// Remove all but the first statement from the node (note that we cannot
	// do this in the previous for loop).
	StmtVector stmtsToRemove(++node->stmt_begin(), node->stmt_end());
	for (const auto &stmt : stmtsToRemove) {
		node->removeStmt(stmt);
	}

	//
	// Then, replace all edges going from the original node with an edge going
	// from lastNode.
	//

	// For each successor of the original node which differs from
	// edgeFromNodeToSecondNode... (Since we're going to call addEdge() from
	// the loop's body, we need to copy the node's successors and iterate over
	// this copy.)
	EdgeVector nodeSuccs(node->succ_begin(), node->succ_end());
	for (auto succ : nodeSuccs) {
		if (succ != edgeFromNodeToSecondNode) {
			addEdge(lastNode, (succ)->getDst(), (succ)->getLabel());
		}
		removeEdge(succ);
	}

	// Leave just the edge going from the original node to the secondly created
	// node.
	if (edgeFromNodeToSecondNode) {
		addEdge(edgeFromNodeToSecondNode->getSrc(), edgeFromNodeToSecondNode->getDst());
	}
}

/**
* @brief Removes nodes with no statements from the CFG.
*
* Let @c A, @c B, and @c be three nodes, where @a A and @c are non-empty and @a
* B is empty, and let them be connected in the following way:
* @code
* A --> B --> C
* @endcode
* Then, this function optimizes this structure into
* @code
* A --> C
* @endcode
*/
void CFG::removeEmptyNodes() {
	// Instead of erasing the node on-the-fly, we insert them into the
	// following set and erase them after we have determined all empty nodes.
	// In this way, we don't have to deal with iterator invalidation.
	NodeSet toEraseNodes;

	// Since more than one iteration may be needed, loop over the CFG until
	// there is no change.
	// TODO Is more than one iteration really needed?
	// TODO Make this more efficient (somehow)?
	bool cfgChanged;
	do {
		cfgChanged = false;

		// For each node...
		for (const auto &node : nodes) {
			if (node->hasStmts() || node == entryNode || node == exitNode) {
				continue;
			}

			// We have found a candidate. It should have only one successor;
			// otherwise, we should not remove it since CFG::removeNode()
			// removes all the edges when the node has more than one successor.
			// TODO What if there is more than one successor? Can this even
			//      happen?
			ASSERT_MSG(node->getNumberOfSuccs() <= 1, "found an empty node with " <<
				node->getNumberOfSuccs() << " successors");

			// "Remove" the node.
			toEraseNodes.insert(node);

			cfgChanged = true;
		}

		// For each node to be removed...
		for (auto node : toEraseNodes) {
			removeNode(node);
		}
	} while (cfgChanged);
}

/**
* @brief Removes unreachable nodes.
*/
void CFG::removeUnreachableNodes() {
	for (auto node : getUnreachableNodes()) {
		if (node != exitNode) {
			removeNode(node);
		}
	}
}

/**
* @brief Asserts out if there is a node whose predecessor/successor is not in
*        @c nodes.
*/
void CFG::validateEveryPredAndSuccIsInNodes() {
	// For every node...
	for (const auto &node : nodes) {
		// For every ingoing edge of the node...
		for (auto i = node->pred_begin(), e = node->pred_end(); i != e; ++i) {
			ASSERT_MSG(hasItem(nodes, (*i)->getSrc()),
				"there is a node which is not in nodes (predecessor)");
		}

		// For every outgoing edge of the node...
		for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
			ASSERT_MSG(hasItem(nodes, (*i)->getDst()),
				"there is a node which is not in nodes (successor)");
		}
	}
}

/**
* @brief Asserts out if there is an empty node in the CFG.
*
* Only nodes different from the entry and exit nodes are checked.
*/
void CFG::validateThereAreNoEmptyNodes() {
	// For each node...
	for (const auto &node : nodes) {
		// Skip the entry and exit nodes.
		if (node == entryNode || node == exitNode) {
			continue;
		}

		ASSERT_MSG(node->hasStmts(), "an empty node (different from the entry"
			" and exit node) has been found");
	}
}

/**
* @brief Asserts out if there is a non-empty statement without a node in the
*        CFG.
*/
void CFG::validateEveryNonEmptyStatementHasNode() {
	// For each node...
	for (const auto &node : nodes) {
		// Skip the entry and exit nodes.
		if (node == entryNode || node == exitNode) {
			continue;
		}

		// For each statement in the node...
		for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
			// Skip empty statements.
			if (isa<EmptyStmt>(*i)) {
				continue;
			}

			ASSERT_MSG(hasNodeForStmt(*i), "found a reachable non-empty "
				"statement '" + (*i)->getTextRepr() + "' that doesn't have an "
				"associated node");
		}
	}
}

/**
* @brief Asserts out if there is an outgoing edge from @c A to @c B but no
*        ingoing edge from @c B to @c A or vice versa in the CFG.
*/
void CFG::validateIngoingAndOutgoingEdges() {
	// For every node...
	for (const auto &node : nodes) {
		// For every ingoing edge of the node...
		for (auto i = node->pred_begin(), e = node->pred_end(); i != e; ++i) {
			ASSERT_MSG((*i)->getSrc()->hasSucc(*i),
				"there is an ingoing edge from " + node->getLabel() + " to " +
				(*i)->getSrc()->getLabel() + " but no corresponding outgoing edge");
		}

		// For every outgoing edge of the node...
		for (auto i = node->succ_begin(), e = node->succ_end(); i != e; ++i) {
			ASSERT_MSG((*i)->getDst()->hasPred(*i),
				"there is an outgoing edge from " + node->getLabel() + " to " +
				(*i)->getDst()->getLabel() + " but no corresponding ingoing edge");
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
