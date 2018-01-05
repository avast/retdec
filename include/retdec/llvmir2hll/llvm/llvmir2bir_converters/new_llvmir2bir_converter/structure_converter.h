/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/structure_converter.h
* @brief A converter of the LLVM function structure.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_STRUCTURE_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_STRUCTURE_CONVERTER_H

#include <functional>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/cfg_node.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class Function;
class Loop;
class LoopInfo;
class Pass;
class ScalarEvolution;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class BasicBlockConverter;
class IfStmt;
class LabelsHandler;
class LLVMValueConverter;
class Statement;
class SwitchStmt;

/**
* @brief Enum class to distinguish when parent of statement is switch or not
*/
enum class SwitchParent {Yes, No};

/**
* @brief A converter of the LLVM function structure.
*/
class StructureConverter final: private retdec::utils::NonCopyable {
private:
	/// Information about state of node during DFS traversal.
	enum class DFSNodeState {
		Opened,  /// Visited, but not closed node.
		Closed   /// Visited and closed node.
	};

	using SwitchClause = std::pair<ExprVector, ShPtr<CFGNode>>;

	using BBSet = std::unordered_set<llvm::BasicBlock *>;
	using CFGNodeQueue = std::queue<ShPtr<CFGNode>>;
	using CFGNodeStack = std::stack<ShPtr<CFGNode>>;
	using CFGNodeVector = std::vector<ShPtr<CFGNode>>;
	using LoopSet = std::unordered_set<llvm::Loop *>;
	using SwitchClauseVector = std::vector<ShPtr<SwitchClause>>;

	using MapBBToBBSet = std::unordered_map<llvm::BasicBlock *, BBSet>;
	using MapBBToCFGNode = std::unordered_map<llvm::BasicBlock *, ShPtr<CFGNode>>;
	using MapCFGNodeToSwitchClause = std::unordered_map<ShPtr<CFGNode>, ShPtr<SwitchClause>>;
	using MapCFGNodeToDFSNodeState = std::unordered_map<ShPtr<CFGNode>, DFSNodeState>;
	using MapLoopToCFGNode = std::unordered_map<llvm::Loop *, ShPtr<CFGNode>>;
	using MapStmtToTargetNode = std::unordered_map<ShPtr<Statement>, ShPtr<CFGNode>>;
	using MapTargetToGoto = std::unordered_map<ShPtr<CFGNode>, std::vector<ShPtr<Statement>>>;
	using MapStmtToClones = std::unordered_map<ShPtr<Statement>, std::vector<ShPtr<Statement>>>;

public:
	StructureConverter(llvm::Pass *basePass, ShPtr<LLVMValueConverter> conv);
	~StructureConverter();

	ShPtr<Statement> convertFuncBody(llvm::Function &func);

private:
	/// @name Construction and traversal through control-flow graph
	/// @{
	ShPtr<CFGNode> createCFG(llvm::BasicBlock &root) const;
	void detectBackEdges(ShPtr<CFGNode> cfg) const;
	bool reduceCFG(ShPtr<CFGNode> cfg);
	bool inspectCFGNode(ShPtr<CFGNode> node);
	ShPtr<CFGNode> popFromQueue(CFGNodeQueue &queue) const;
	void addUnvisitedSuccessorsToQueue(const ShPtr<CFGNode> &node,
		CFGNodeQueue &toBeVisited, CFGNode::CFGNodeSet &visited) const;
	void addUnvisitedSuccessorsToQueueInLoop(const ShPtr<CFGNode> &node,
		CFGNodeQueue &toBeVisited, CFGNode::CFGNodeSet &visited,
		llvm::Loop *loop) const;
	bool BFSTraverse(ShPtr<CFGNode> cfg,
		std::function<bool (ShPtr<CFGNode>)> inspectFunc) const;
	bool BFSTraverseLoop(ShPtr<CFGNode> cfg,
		std::function<bool (ShPtr<CFGNode>)> inspectFunc) const;
	ShPtr<CFGNode> BFSFindFirst(ShPtr<CFGNode> cfg,
		std::function<bool (ShPtr<CFGNode>)> pred) const;
	bool existsPathWithoutLoopsBetween(const ShPtr<CFGNode> &node1,
		const ShPtr<CFGNode> &node2) const;
	/// @}

	/// @name Detection of constructions
	/// @{
	bool isSequence(const ShPtr<CFGNode> &node) const;
	bool isSequenceWithTerminatingBranchToClone(
		const ShPtr<CFGNode> &node) const;
	bool isIfElseStatement(const ShPtr<CFGNode> &node) const;
	bool isIfStatement(const ShPtr<CFGNode> &node, std::size_t succ) const;
	bool isIfStatementWithTerminatingBranch(const ShPtr<CFGNode> &node,
		std::size_t succ) const;
	bool isIfStatementWithTerminatingBranchToClone(const ShPtr<CFGNode> &node,
		std::size_t succ) const;
	bool isIfStatementWithBreakInLoop(const ShPtr<CFGNode> &node,
		std::size_t succ) const;
	bool isIfStatementWithBreakByGotoInLoop(const ShPtr<CFGNode> &node,
		std::size_t succ) const;
	bool isIfElseStatementWithContinue(const ShPtr<CFGNode> &node,
		std::size_t succ) const;
	bool isContinueStatement(const ShPtr<CFGNode> &node) const;
	bool isForLoop(const ShPtr<CFGNode> &node) const;
	bool isWhileTrueLoop(const ShPtr<CFGNode> &node) const;
	bool isNestedWhileTrueLoopWithContinueInHeader(const ShPtr<CFGNode> &node,
		std::size_t succ) const;
	bool isSwitchStatement(const ShPtr<CFGNode> &node) const;
	bool canBeCloned(const ShPtr<CFGNode> &node) const;
	/// @}

	/// @name Reduction of nodes
	/// @{
	void reduceToSequence(ShPtr<CFGNode> node);
	void reduceToSequenceClone(ShPtr<CFGNode> node);
	void reduceToIfElseStatement(ShPtr<CFGNode> node);
	void reduceToIfStatement(ShPtr<CFGNode> node, std::size_t succ);
	void reduceToIfStatementClone(ShPtr<CFGNode> node, std::size_t succ);
	void reduceToIfElseStatementWithBreakInLoop(ShPtr<CFGNode> node,
		std::size_t succ);
	void reduceToIfElseStatementWithBreakByGotoInLoop(ShPtr<CFGNode> node,
		std::size_t succ);
	void reduceToIfElseStatementWithContinue(ShPtr<CFGNode> node,
		std::size_t succ);
	void reduceToContinueStatement(ShPtr<CFGNode> node);
	void reduceToForLoop(ShPtr<CFGNode> node);
	void reduceToWhileTrueLoop(ShPtr<CFGNode> node);
	void reduceToNestedWhileTrueLoopWithContinueInHeader(
		ShPtr<CFGNode> node, std::size_t succ);
	void structureByGotos(ShPtr<CFGNode> cfg);
	/// @}

	/// @name Condition refinement
	/// @{
	ShPtr<Statement> getIfClauseBody(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &clause, const ShPtr<CFGNode> &ifSuccessor);
	ShPtr<Statement> getIfClauseBodyClone(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &clause, const ShPtr<CFGNode> &ifSuccessor);
	ShPtr<IfStmt> getIfStmt(const ShPtr<Expression> &cond,
		const ShPtr<Statement> &trueBody,
		const ShPtr<Statement> &falseBody = nullptr) const;
	/// @}

	/// @name Loop refinement
	/// @{
	ShPtr<CFGNode> getLoopSuccessor(const ShPtr<CFGNode> &loopNode) const;
	void completelyReduceLoop(ShPtr<CFGNode> loopNode);
	/// @}

	/// @name Switch refinement
	/// @{
	void reduceSwitchStatement(ShPtr<CFGNode> node);
	ShPtr<CFGNode> getSwitchSuccessor(const ShPtr<CFGNode> &switchNode) const;
	bool isNodeAfterAllSwitchClauses(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &switchNode) const;
	bool isNodeAfterSwitchClause(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &clauseNode) const;
	bool hasDefaultClause(const ShPtr<CFGNode> &switchNode,
		const ShPtr<CFGNode> &switchSuccessor) const;
	bool isReducibleClause(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode,
		const ShPtr<CFGNode> &switchSuccessor,
		bool hasDefault = true) const;
	bool hasOnlySwitchOrClausesInPreds(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode, bool hasDefault) const;
	bool fallsThroughToAnotherCase(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode, bool hasDefault) const;
	ShPtr<SwitchStmt> getSwitchStmt(const ShPtr<CFGNode> &switchNode,
		const ShPtr<CFGNode> &switchSuccessor, bool hasDefault);
	SwitchClauseVector getSwitchClauses(const ShPtr<CFGNode> &switchNode,
		bool hasDefault) const;
	SwitchClauseVector sortSwitchClauses(const SwitchClauseVector &clauses,
		const ShPtr<CFGNode> &switchSuccessor) const;
	ShPtr<SwitchClause> findFirstClauseWithSinglePred(
		const SwitchClauseVector &clauses) const;
	ShPtr<Statement> getClauseBody(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode,
		const ShPtr<CFGNode> &switchSuccessor,
		const CFGNode::CFGNodeSet &generated);
	bool isClauseTerminatedByBreak(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchSuccessor) const;
	void addClausesWithTheSameCond(ShPtr<SwitchStmt> switchStmt,
		const ExprVector &conds, const ShPtr<Statement> &clauseBody) const;
	void removeReducedSuccsOfSwitch(const ShPtr<CFGNode> &switchNode,
		bool hasDefault) const;
	/// @}

	/// @name Successor getters
	/// @{
	ShPtr<Statement> getSuccessorsBody(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &succ);
	ShPtr<Statement> getSuccessorsBodyClone(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &succ);
	ShPtr<Statement> getGotoForSuccessor(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &target);
	ShPtr<Statement> getAssignsToPHINodes(const ShPtr<CFGNode> &from,
		const ShPtr<CFGNode> &to);
	ShPtr<Statement> getPHICopiesForSuccessor(llvm::BasicBlock *currBB,
		llvm::BasicBlock *succ);
	/// @}

	/// @name Work with LLVM analyses
	/// @{
	void initialiazeLLVMAnalyses(llvm::Function &func);
	llvm::Loop *getLoopFor(const ShPtr<CFGNode> &node) const;
	bool isLoopHeader(const ShPtr<CFGNode> &node) const;
	bool isLoopHeader(const ShPtr<CFGNode> &node, llvm::Loop *loop) const;
	bool isNodeOutsideLoop(const ShPtr<CFGNode> &node, llvm::Loop *loop) const;
	bool isInParentLoopOf(const ShPtr<CFGNode> &node, llvm::Loop *loop) const;
	unsigned getTripCount(llvm::Loop *loop) const;
	bool canBeForLoop(llvm::Loop *loop) const;
	/// @}

	/// @name Postprocessing methods
	/// @{
	ShPtr<Statement> replaceBreakOrContinueOutsideLoop(
		ShPtr<Statement> statement, SwitchParent sp);
	void replaceGoto(CFGNodeVector &targets);
	void correctUndefinedLabels();
	std::vector<ShPtr<Statement>> findContinueOrBreakStatements(
		ShPtr<Statement> parent, SwitchParent sp);
	unsigned getStatementCount(ShPtr<Statement> statement);
	void insertClonedLoopTargets( ShPtr<Statement> origParent,
		ShPtr<Statement> newParent);
	ShPtr<Statement> deepCloneStatements(ShPtr<Statement> orig);
	/// @}

	/// @name Helper methods
	/// @{
	void addGotoTargetIfNotExists(const ShPtr<CFGNode> &node);
	void addBranchMetadataToEndOfBodyIfNeeded(ShPtr<Statement> &body,
		const ShPtr<CFGNode> &clause, const ShPtr<CFGNode> &ifSuccessor) const;
	std::string getLabel(const ShPtr<CFGNode> &node) const;
	void cleanUp();
	/// @}

	/// Pass that have instantiated the converter.
	llvm::Pass *basePass;

	/// Information about loops.
	llvm::LoopInfo *loopInfo;

	// Anylysis of scalar expressions in loops.
	llvm::ScalarEvolution *scalarEvolution;

	/// A handler of labels.
	ShPtr<LabelsHandler> labelsHandler;

	/// A converter of the LLVM basic block.
	UPtr<BasicBlockConverter> bbConverter;

	/// A converter from LLVM values to values in BIR.
	ShPtr<LLVMValueConverter> converter;

	/// A map of the corresponding loops and loop headers represented
	/// by CFG nodes.
	MapLoopToCFGNode loopHeaders;

	/// A map of already generated phi nodes from specific basic blocks.
	MapBBToBBSet generatedPHINodes;

	/// A map of targets for break and continue statements
	MapStmtToTargetNode loopTargets;

	/// A map of references for goto targets
	MapTargetToGoto targetReferences;

	/// A map of clones of statement
	MapStmtToClones stmtClones;

	// A set of already reduced loops.
	LoopSet reducedLoops;

	// A set of already reduced loops.
	BBSet reducedSwitches;

	// A stack representing hierarchy of the parent statements during structuring.
	CFGNodeStack statementsStack;

	// A set of statements that are already on the stack.
	CFGNode::CFGNodeSet statementsOnStack;

	// A vector of nodes, which are targets of goto.
	CFGNodeVector gotoTargets;

	// A set of nodes, which are targets of goto.
	CFGNode::CFGNodeSet gotoTargetsSet;

	// A set of nodes, which are already generated to the resulting code.
	CFGNode::CFGNodeSet generatedNodes;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
