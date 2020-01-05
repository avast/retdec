/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter/cfg_node.h
* @brief A representation of a control-flow graph node.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_CFG_NODE_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_CFG_NODE_H

#include <string>
#include <unordered_set>
#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class BasicBlock;
class Instruction;
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
		CFGEdge(CFGNode* target);

		CFGNode* getTarget() const;
		bool isBackEdge() const;

		void setBackEdge(bool isBackEdge = true);

	private:
		/// A target of this edge.
		CFGNode* target = nullptr;

		/// Is this edge a back-edge?
		bool backEdge;
	};

public:
	using CFGEdgeVector = std::vector<CFGEdge*>;
	using CFGNodeSet = std::unordered_set<CFGNode*>;
	using CFGNodeVector = std::vector<CFGNode*>;

public:
	CFGNode(llvm::BasicBlock *bb, Statement* body);

	/// @name Operations with stored basic blocks
	/// @{
	llvm::BasicBlock *getFirstBB() const;
	llvm::BasicBlock *getLastBB() const;
	void setLastBB(llvm::BasicBlock *bb);
	/// @}

	/// @name Operations with terminator instruction of the last basic block
	/// @{
	llvm::Instruction *getTerm() const;
	llvm::Value *getCond() const;
	/// @}

	/// @name Operations with node's body
	/// @{
	Statement* getBody() const;
	void setBody(Statement* body);
	void appendToBody(Statement* statement);
	/// @}

	/// @name Addition and deletion of the node's successors
	/// @{
	void addSuccessor(CFGNode* succ);
	void moveSuccessorsFrom(CFGNode* node);
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
	CFGNodeSet getPredecessors() const;
	CFGNodeVector getSuccessors() const;
	CFGNode* getSucc(std::size_t i) const;
	CFGNode* getSuccOrNull(std::size_t i) const;
	bool hasSuccessor(CFGNode* node) const;
	/// @}

	/// @name Operations with back-edges
	/// @{
	void markAsBackEdge(CFGNode* node);
	bool isBackEdge(CFGNode* node) const;
	/// @}

	/// @name Operations with statement successor
	/// @{
	bool hasStatementSuccessor() const;
	CFGNode* getStatementSuccessor() const;
	void setStatementSuccessor(CFGNode* succ);
	void removeStatementSuccessor();
	/// @}

	/// @name Debugging methods
	/// @{
	std::string getName() const;
	void debugPrint() const;
	/// @}

private:
	/// A first LLVM basic block in sequence which is represented by this node.
	llvm::BasicBlock *firstBasicBlock = nullptr;

	/// A last LLVM basic block in sequence which is represented by this node.
	llvm::BasicBlock *lastBasicBlock = nullptr;

	/// A body of this tree node.
	Statement* body = nullptr;

	/// A set of node predecessors.
	CFGNodeSet predecessors;

	/// An ordered vector of node successors.
	CFGEdgeVector successors;

	/// A successor of the high-level statement represented by this node.
	CFGNode* statementSuccessor = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
