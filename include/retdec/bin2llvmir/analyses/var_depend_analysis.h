/**
* @file include/retdec/bin2llvmir/analyses/var_depend_analysis.h
* @brief Analysis for variable dependency of PHINodes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_VAR_DEPEND_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_VAR_DEPEND_ANALYSIS_H

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>

namespace retdec {
namespace bin2llvmir {

/**
* @brief Analysis of variable dependency of PHI Nodes.
*
* This class supports two things:
* - Detects the cycles and return PHI nodes that have to be optimized to remove
*   the cycles.
* - Makes an analysis that returns PHI nodes in order that sequential
*   processing of PHI nodes is equivalent with parallel processing.
*/
class VarDependAnalysis {
public:
	/// Vector of PHI nodes.
	using PHINodeVec = std::vector<llvm::PHINode *>;

	/**
	* @brief Basic block with vector of PHI nodes.
	*/
	struct BBVecOfPHINodes {
		/**
		* @brief Constructs a new @c std::vector<llvm::BasicBlock*>OfPHINodes.
		*
		* @param[in] bb Basic block that identifies PHI nodes in @a vecOfPHINodes.
		* @param[in] vecOfPHINodes Vector of PHI nodes.
		*/
		BBVecOfPHINodes(llvm::BasicBlock *bb, PHINodeVec
			vecOfPHINodes): bb(bb), phiNodeVec(vecOfPHINodes) {}

		/**
		* @brief Move constructor.
		*
		* @param[in] other This value is moved.
		*/
		BBVecOfPHINodes(BBVecOfPHINodes &&other): bb(other.bb),
			phiNodeVec(std::move(other.phiNodeVec)) {}

		/// Basic block that identifies PHI nodes.
		llvm::BasicBlock *bb;

		/// Vector of PHI nodes that have to be optimized.
		PHINodeVec phiNodeVec;
	};

	/// Map of string to basic block with vector of PHI nodes.
	using StringBBVecOfPHINodesMap = std::map<std::string, BBVecOfPHINodes>;

public:
	VarDependAnalysis();
	~VarDependAnalysis();

	std::string getId() const { return "VarDependAnalysis"; }

	void addEdge(const std::string &srcNodeName, const std::string &dstNodeName,
		llvm::BasicBlock &incBB, llvm::PHINode *phiNode);
	void clear();
	const StringBBVecOfPHINodesMap &detectCycleVarDependency();
	const PHINodeVec &detectNonCycleVarDependency();

private:
	/**
	* @brief Node of graph.
	*/
	class Node {
	public:
		/**
		* @brief Successor node with basic block.
		*/
		struct Successor {
			/**
			* @brief Constructs a new @c Successor.
			*
			* @param[in] succ Successor node.
			* @param[in] incBB Incoming basic block.
			*/
			Successor(Node *succ, llvm::BasicBlock &incBB): succ(succ) {
				incBBs.insert(&incBB);
			}

			/**
			* @brief Move constructor.
			*
			* @param[in] other This value is moved.
			*/
			Successor(Successor &&other): succ(other.succ),
				incBBs(std::move(other.incBBs)) {}

			void print();

			/// Successor node.
			Node *succ;

			/// Basic block that characterize successor.
			std::set<llvm::BasicBlock*> incBBs;
		};

		/// Mapping a string to successor.
		using SuccMap = std::map<std::string, Successor>;

	public:
		Node(const std::string &name, llvm::PHINode *phiNode = nullptr);
		~Node();

		void addSucc(Node &succ, llvm::BasicBlock &incBB);
		void markAsSolved();
		void markAsVisited();
		void markAsNotSolved();
		void markAsNotVisited();
		void markAsSolvedAndNotVisited();

		void print();

	public:
		/// Mapping destination node to successors for source node.
		SuccMap succMap;

		/// Name of node.
		std::string name;

		/// PHI node for this node.
		llvm::PHINode *phiNode;

		/// Signalizes if this node was visited.
		bool visited;

		/// Signalized if this node was solved.
		bool solved;
	};

	/// String to Node map.
	using StringNodeMap = std::map<std::string, Node *>;

	/// Vector of nodes.
	using NodeVec = std::vector<Node *>;

private:
	void addResultOfCycle(Node::Successor &successor);
	Node &findOrCreateNode(const std::string &nodeName);
	void iterateThroughNodesCycleDetect();
	void iterateThroughNodesNonCycleVarDependency();
	void iterateThroughSuccessorsAndVisitTheirNode(Node &node);
	Node *visitNodeCycleDetect(VarDependAnalysis::Node &node);
	void visitNodeNonCycleVarDependency(VarDependAnalysis::Node &node);
	void setAllNodesAsNotSolved();

	void print();

private:
	/// Mapping of a name of node to nodes.
	StringNodeMap nodeMap;

	/// This vector is used for ensure the same order of PHI nodes when we don't
	/// need any optimization.
	NodeVec nodeVec;

	/// Result of cycles analysis.
	StringBBVecOfPHINodesMap resultForCycles;

	/// Result of non-cycle variable dependency analysis.
	PHINodeVec resultOfNonCycle;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
