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
	using NodeVector = std::vector<ShPtr<Node>>;

	/// Nodes iterator.
	using node_iterator = NodeVector::const_iterator;

	/// Vector of edges.
	using EdgeVector = std::vector<ShPtr<Edge>>;

	/// Edges iterator.
	using edge_iterator = EdgeVector::const_iterator;

	/// Successors iterator.
	using succ_iterator = EdgeVector::const_iterator;

	/// Predecessors iterator.
	using pred_iterator = EdgeVector::const_iterator;

	/// Statement in a node (first -> node, second -> position of the statement
	/// within the node).
	using StmtInNode = std::pair<ShPtr<Node>, stmt_iterator>;

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
		~Node();

		std::string getLabel() const;

		/// @name Statements Accessors
		/// @{
		bool hasStmts() const;
		std::size_t getNumberOfStmts() const;
		void addStmt(ShPtr<Statement> stmt);
		void replaceStmt(ShPtr<Statement> stmt, const StmtVector &stmts);
		void removeStmt(ShPtr<Statement> stmt);

		stmt_iterator stmt_begin() const;
		stmt_iterator stmt_end() const;

		stmt_reverse_iterator stmt_rbegin() const;
		stmt_reverse_iterator stmt_rend() const;
		/// @}

		/// @name Successors Accessors
		/// @{
		bool hasSuccs() const;
		bool hasSucc(ShPtr<Edge> edge) const;
		std::size_t getNumberOfSuccs() const;
		void addSucc(ShPtr<Edge> succ);
		ShPtr<Edge> getFirstSucc() const;
		void removeSucc(ShPtr<Edge> succ);

		succ_iterator succ_begin() const;
		succ_iterator succ_end() const;
		/// @}

		/// @name Predecessors Accessors
		/// @{
		bool hasPreds() const;
		bool hasPred(ShPtr<Edge> edge) const;
		std::size_t getNumberOfPreds() const;
		void addPred(ShPtr<Edge> pred);
		void removePred(ShPtr<Edge> succ);

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
		Edge(ShPtr<Node> src, ShPtr<Node> dst,
			ShPtr<Expression> label = nullptr);
		~Edge();

		ShPtr<Node> getSrc() const;
		ShPtr<Expression> getLabel() const;
		ShPtr<Node> getDst() const;

	private:
		/// Edge source.
		ShPtr<Node> src;

		/// Edge label.
		ShPtr<Expression> label;

		/// Edge destination.
		ShPtr<Node> dst;
	};

public:
	CFG(ShPtr<Function> func);
	~CFG();

	ShPtr<Function> getCorrespondingFunction() const;

	/// @name Nodes Accessors
	/// @{
	std::size_t getNumberOfNodes() const;
	void addEntryNode(ShPtr<Node> node);
	void addExitNode(ShPtr<Node> node);
	ShPtr<Node> getEntryNode() const;
	ShPtr<Node> getExitNode() const;
	NodeVector getUnreachableNodes() const;
	bool stmtExistsInCFG(ShPtr<Statement> stmt) const;
	StmtInNode getNodeForStmt(ShPtr<Statement> stmt) const;
	stmt_reverse_iterator getReverseIteratorFromIterator(stmt_iterator i);
	bool hasNodeForStmt(ShPtr<Statement> stmt) const;
	void addNode(ShPtr<Node> node);
	void splitNodes();
	void removeNode(ShPtr<Node> node);
	void removeEmptyNodes();
	void removeUnreachableNodes();
	void removeStmtFromNode(ShPtr<Statement> stmt, ShPtr<CFG::Node> node);
	void removeStmt(ShPtr<Statement> stmt);
	void replaceStmt(ShPtr<Statement> stmt, const StmtVector &stmts);

	static ShPtr<Statement> getLastStmtInNode(ShPtr<Node> node);

	node_iterator node_begin() const;
	node_iterator node_end() const;
	/// @}

	/// @name Edges Accessors
	/// @{
	ShPtr<Edge> addEdge(ShPtr<Node> src, ShPtr<Node> dst,
		ShPtr<Expression> label = nullptr);
	void removeEdge(ShPtr<Edge> edge);

	edge_iterator edge_begin() const;
	edge_iterator edge_end() const;
	/// @}

private:
	/// Mapping of a statement into its corresponding node.
	using StmtNodeMapping = std::unordered_map<ShPtr<Statement>, ShPtr<Node>>;

private:
	ShPtr<Node> addNode(const std::string &label = "");

	void splitNode(ShPtr<Node> node);

	/// @name Validation
	/// @{
	void validateEveryPredAndSuccIsInNodes();
	void validateThereAreNoEmptyNodes();
	void validateEveryNonEmptyStatementHasNode();
	void validateIngoingAndOutgoingEdges();
	/// @}

private:
	/// Function to which this CFG corresponds.
	ShPtr<Function> correspondingFunction;

	/// Vector of nodes.
	NodeVector nodes;

	/// Vector of edges.
	EdgeVector edges;

	/// Entry node.
	ShPtr<Node> entryNode;

	/// Exit node.
	ShPtr<Node> exitNode;

	/// Mapping between a statement and a node in which the statement is.
	StmtNodeMapping stmtNodeMapping;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
