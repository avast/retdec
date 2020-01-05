/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg.h
* @brief A representation of a control-flow graph (CFG).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_H

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Function;
class Statement;

/**
* @brief A representation of a control-flow graph (CFG).
*
* See http://en.wikipedia.org/wiki/Control_flow_graph.
*
* Empty statements are never present in a CFG.
*
* Use a subclass of CFGBuilder to create instances of this class. Whenever the
* underlying backend IR (= code of the function) is changed, like a statement
* is removed, the CFG is invalidated and has to be re-built.
*
* Instances of this class have reference object semantics.
*
* This class is not meant to be subclassed.
*/
class CFG final: private retdec::utils::NonCopyable {
	friend class RecursiveCFGBuilder;
	friend class NonRecursiveCFGBuilder;
public:
	class Node;
	class Edge;

	/// Statements iterator.
	using stmt_iterator = StmtVector::const_iterator;

	/// Statements reverse iterator.
	using stmt_reverse_iterator = StmtVector::const_reverse_iterator;

	/// Vector of nodes.
	using NodeVector = std::vector<Node*>;

	/// Nodes iterator.
	using node_iterator = NodeVector::const_iterator;

	/// Vector of edges.
	using EdgeVector = std::vector<Edge*>;

	/// Edges iterator.
	using edge_iterator = EdgeVector::const_iterator;

	/// Successors iterator.
	using succ_iterator = EdgeVector::const_iterator;

	/// Predecessors iterator.
	using pred_iterator = EdgeVector::const_iterator;

	/// Statement in a node (first -> node, second -> position of the statement
	/// within the node).
	using StmtInNode = std::pair<Node*, stmt_iterator>;

	/**
	* @brief A node of a CFG (represents a basic block).
	*
	* Instances of this class have reference object semantics.
	*/
	class Node: private retdec::utils::NonCopyable {
		friend class RecursiveCFGBuilder;
		friend class NonRecursiveCFGBuilder;
	public:
		Node();
		explicit Node(const std::string &label);

		std::string getLabel() const;

		/// @name Statements Accessors
		/// @{
		bool hasStmts() const;
		std::size_t getNumberOfStmts() const;
		void addStmt(Statement* stmt);
		void replaceStmt(Statement* stmt, const StmtVector &stmts);
		void removeStmt(Statement* stmt);

		stmt_iterator stmt_begin() const;
		stmt_iterator stmt_end() const;

		stmt_reverse_iterator stmt_rbegin() const;
		stmt_reverse_iterator stmt_rend() const;
		/// @}

		/// @name Successors Accessors
		/// @{
		bool hasSuccs() const;
		bool hasSucc(Edge* edge) const;
		std::size_t getNumberOfSuccs() const;
		void addSucc(Edge* succ);
		Edge* getFirstSucc() const;
		void removeSucc(Edge* succ);

		succ_iterator succ_begin() const;
		succ_iterator succ_end() const;
		/// @}

		/// @name Predecessors Accessors
		/// @{
		bool hasPreds() const;
		bool hasPred(Edge* edge) const;
		std::size_t getNumberOfPreds() const;
		void addPred(Edge* pred);
		void removePred(Edge* succ);

		pred_iterator pred_begin() const;
		pred_iterator pred_end() const;
		/// @}

	private:
		/// Label.
		std::string label;

		/// Vector of statements forming a basic block.
		StmtVector stmts;

		/// Vector of edges leaving the node.
		EdgeVector succs;

		/// Vector of edges entering the node.
		EdgeVector preds;
	};

	/**
	* @brief An edge of a CFG (represents program flow).
	*
	* Instances of this class have reference object semantics.
	*/
	class Edge: private retdec::utils::NonCopyable {
		friend class RecursiveCFGBuilder;
		friend class NonRecursiveCFGBuilder;
	public:
		Edge(Node* src, Node* dst,
			Expression* label = nullptr);

		Node* getSrc() const;
		Expression* getLabel() const;
		Node* getDst() const;

	private:
		/// Edge source.
		Node* src = nullptr;

		/// Edge label.
		Expression* label = nullptr;

		/// Edge destination.
		Node* dst = nullptr;
	};

public:
	CFG(Function* func);

	Function* getCorrespondingFunction() const;

	/// @name Nodes Accessors
	/// @{
	std::size_t getNumberOfNodes() const;
	void addEntryNode(Node* node);
	void addExitNode(Node* node);
	Node* getEntryNode() const;
	Node* getExitNode() const;
	NodeVector getUnreachableNodes() const;
	bool stmtExistsInCFG(Statement* stmt) const;
	StmtInNode getNodeForStmt(Statement* stmt) const;
	stmt_reverse_iterator getReverseIteratorFromIterator(stmt_iterator i);
	bool hasNodeForStmt(Statement* stmt) const;
	void addNode(Node* node);
	void splitNodes();
	void removeNode(Node* node);
	void removeEmptyNodes();
	void removeUnreachableNodes();
	void removeStmtFromNode(Statement* stmt, CFG::Node* node);
	void removeStmt(Statement* stmt);
	void replaceStmt(Statement* stmt, const StmtVector &stmts);

	static Statement* getLastStmtInNode(Node* node);

	node_iterator node_begin() const;
	node_iterator node_end() const;
	/// @}

	/// @name Edges Accessors
	/// @{
	Edge* addEdge(Node* src, Node* dst,
		Expression* label = nullptr);
	void removeEdge(Edge* edge);

	edge_iterator edge_begin() const;
	edge_iterator edge_end() const;
	/// @}

private:
	/// Mapping of a statement into its corresponding node.
	using StmtNodeMapping = std::unordered_map<Statement*, Node*>;

private:
	Node* addNode(const std::string &label = "");

	void splitNode(Node* node);

	/// @name Validation
	/// @{
	void validateEveryPredAndSuccIsInNodes();
	void validateThereAreNoEmptyNodes();
	void validateEveryNonEmptyStatementHasNode();
	void validateIngoingAndOutgoingEdges();
	/// @}

private:
	/// Function to which this CFG corresponds.
	Function* correspondingFunction = nullptr;

	/// Vector of nodes.
	NodeVector nodes;

	/// Vector of edges.
	EdgeVector edges;

	/// Entry node.
	Node* entryNode = nullptr;

	/// Exit node.
	Node* exitNode = nullptr;

	/// Mapping between a statement and a node in which the statement is.
	StmtNodeMapping stmtNodeMapping;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
