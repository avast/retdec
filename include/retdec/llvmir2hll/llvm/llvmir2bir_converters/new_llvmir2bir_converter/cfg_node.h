/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/cfg_node.h
* @brief A representation of a control-flow graph node.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_CFG_NODE_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_CFG_NODE_H

#include <string>
#include <unordered_set>
#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class BasicBlock;
class TerminatorInst;
class Value;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class Statement;

/**
* @brief A representation of a control-flow graph node.
*/
class CFGNode: public SharableFromThis<CFGNode>,
	private retdec::utils::NonCopyable {
private:
	/**
	* @brief A representation of a control-flow graph edge.
	*/
	class CFGEdge: private retdec::utils::NonCopyable {
	public:
		CFGEdge(ShPtr<CFGNode> target);

		ShPtr<CFGNode> getTarget() const;
		bool isBackEdge() const;

		void setBackEdge(bool isBackEdge = true);

	private:
		/// A target of this edge.
		ShPtr<CFGNode> target;

		/// Is this edge a back-edge?
		bool backEdge;
	};

public:
	using CFGEdgeVector = std::vector<ShPtr<CFGEdge>>;
	using CFGNodeSet = std::unordered_set<ShPtr<CFGNode>>;
	using CFGNodeVector = std::vector<ShPtr<CFGNode>>;

public:
	CFGNode(llvm::BasicBlock *bb, ShPtr<Statement> body);

	/// @name Operations with stored basic blocks
	/// @{
	llvm::BasicBlock *getFirstBB() const;
	llvm::BasicBlock *getLastBB() const;
	void setLastBB(llvm::BasicBlock *bb);
	/// @}

	/// @name Operations with terminator instruction of the last basic block
	/// @{
	llvm::TerminatorInst *getTerm() const;
	llvm::Value *getCond() const;
	/// @}

	/// @name Operations with node's body
	/// @{
	ShPtr<Statement> getBody() const;
	void setBody(ShPtr<Statement> body);
	void appendToBody(ShPtr<Statement> statement);
	/// @}

	/// @name Addition and deletion of the node's successors
	/// @{
	void addSuccessor(ShPtr<CFGNode> succ);
	void moveSuccessorsFrom(const ShPtr<CFGNode> &node);
	void removeSucc(std::size_t i);
	void deleteSucc(std::size_t i);
	void deleteSuccessors();
	/// @}

	/// @name Getters for number of predecessors and successors
	/// @{
	std::size_t getPredsNum() const;
	std::size_t getSuccNum() const;
	/// @}

	/// @name Node's successors getters and querying
	/// @{
	CFGNodeSet getPredecessors();
	CFGNodeVector getSuccessors();
	ShPtr<CFGNode> getSucc(std::size_t i) const;
	ShPtr<CFGNode> getSuccOrNull(std::size_t i) const;
	bool hasSuccessor(const ShPtr<CFGNode> &node) const;
	/// @}

	/// @name Operations with back-edges
	/// @{
	void markAsBackEdge(const ShPtr<CFGNode> &node);
	bool isBackEdge(const ShPtr<CFGNode> &node) const;
	/// @}

	/// @name Operations with statement successor
	/// @{
	bool hasStatementSuccessor() const;
	ShPtr<CFGNode> getStatementSuccessor() const;
	void setStatementSuccessor(ShPtr<CFGNode> succ);
	void removeStatementSuccessor();
	/// @}

	/// @name Debugging methods
	/// @{
	std::string getName() const;
	void debugPrint() const;
	/// @}

private:
	/// A first LLVM basic block in sequence which is represented by this node.
	llvm::BasicBlock *firstBasicBlock;

	/// A last LLVM basic block in sequence which is represented by this node.
	llvm::BasicBlock *lastBasicBlock;

	/// A body of this tree node.
	ShPtr<Statement> body;

	/// A set of node predecessors.
	CFGNodeSet predecessors;

	/// An ordered vector of node successors.
	CFGEdgeVector successors;

	/// A successor of the high-level statement represented by this node.
	ShPtr<CFGNode> statementSuccessor;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
