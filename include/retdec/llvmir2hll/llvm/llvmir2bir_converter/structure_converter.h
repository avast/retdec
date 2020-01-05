/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converter/structure_converter.h
* @brief A converter of the LLVM function structure.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_STRUCTURE_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTER_STRUCTURE_CONVERTER_H

#include <functional>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/basic_block_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter/cfg_node.h"
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

	using SwitchClause = std::pair<ExprVector, CFGNode*>;

	using BBSet = std::unordered_set<llvm::BasicBlock *>;
	using CFGNodeQueue = std::queue<CFGNode*>;
	using CFGNodeStack = std::stack<CFGNode*>;
	using CFGNodeVector = std::vector<CFGNode*>;
	using LoopSet = std::unordered_set<llvm::Loop *>;
	using SwitchClauseVector = std::vector<SwitchClause*>;

	using MapBBToBBSet = std::unordered_map<llvm::BasicBlock *, BBSet>;
	using MapBBToCFGNode = std::unordered_map<llvm::BasicBlock *, CFGNode*>;
	using MapCFGNodeToSwitchClause = std::unordered_map<CFGNode*, SwitchClause*>;
	using MapCFGNodeToDFSNodeState = std::unordered_map<CFGNode*, DFSNodeState>;
	using MapLoopToCFGNode = std::unordered_map<llvm::Loop *, CFGNode*>;
	using MapStmtToTargetNode = std::unordered_map<Statement*, CFGNode*>;
	using MapTargetToGoto = std::unordered_map<CFGNode*, std::vector<GotoStmt*>>;
	using MapStmtToClones = std::unordered_map<Statement*, std::vector<Statement*>>;

public:
	StructureConverter(llvm::Pass *basePass, LLVMValueConverter* conv, Module* module);

	Statement* convertFuncBody(llvm::Function &func);

private:
	/// @name Construction and traversal through control-flow graph
	/// @{
	CFGNode* createCFG(llvm::BasicBlock &root);
	void detectBackEdges(CFGNode* cfg) const;
	bool reduceCFG(CFGNode* cfg);
	bool inspectCFGNode(CFGNode* node);
	CFGNode* popFromQueue(CFGNodeQueue &queue) const;
	void addUnvisitedSuccessorsToQueue(CFGNode* node,
		CFGNodeQueue &toBeVisited, CFGNode::CFGNodeSet &visited) const;
	void addUnvisitedSuccessorsToQueueInLoop(CFGNode* node,
		CFGNodeQueue &toBeVisited, CFGNode::CFGNodeSet &visited,
		llvm::Loop *loop) const;
	bool BFSTraverse(CFGNode* cfg,
		std::function<bool (CFGNode*)> inspectFunc) const;
	bool BFSTraverseLoop(CFGNode* cfg,
		std::function<bool (CFGNode*)> inspectFunc) const;
	CFGNode* BFSFindFirst(CFGNode* cfg,
		std::function<bool (CFGNode*)> pred) const;
	bool existsPathWithoutLoopsBetween(CFGNode* node1,
		CFGNode* node2) const;
	/// @}

	/// @name Detection of constructions
	/// @{
	bool isSequence(CFGNode* node) const;
	bool isSequenceWithTerminatingBranchToClone(
		CFGNode* node) const;
	bool isIfElseStatement(CFGNode* node) const;
	bool isIfStatement(CFGNode* node, std::size_t succ) const;
	bool isIfStatementWithTerminatingBranch(CFGNode* node,
		std::size_t succ) const;
	bool isIfStatementWithTerminatingBranchToClone(CFGNode* node,
		std::size_t succ) const;
	bool isIfStatementWithBreakInLoop(CFGNode* node,
		std::size_t succ) const;
	bool isIfStatementWithBreakByGotoInLoop(CFGNode* node,
		std::size_t succ) const;
	bool isIfElseStatementWithContinue(CFGNode* node,
		std::size_t succ) const;
	bool isContinueStatement(CFGNode* node) const;
	bool isForLoop(CFGNode* node) const;
	bool isWhileTrueLoop(CFGNode* node) const;
	bool isNestedWhileTrueLoopWithContinueInHeader(CFGNode* node,
		std::size_t succ) const;
	bool isSwitchStatement(CFGNode* node) const;
	bool canBeCloned(CFGNode* node) const;
	/// @}

	/// @name Reduction of nodes
	/// @{
	void reduceToSequence(CFGNode* node);
	void reduceToSequenceClone(CFGNode* node);
	void reduceToIfElseStatement(CFGNode* node);
	void reduceToIfStatement(CFGNode* node, std::size_t succ);
	void reduceToIfStatementClone(CFGNode* node, std::size_t succ);
	void reduceToIfElseStatementWithBreakInLoop(CFGNode* node,
		std::size_t succ);
	void reduceToIfElseStatementWithBreakByGotoInLoop(CFGNode* node,
		std::size_t succ);
	void reduceToIfElseStatementWithContinue(CFGNode* node,
		std::size_t succ);
	void reduceToContinueStatement(CFGNode* node);
	void reduceToForLoop(CFGNode* node);
	void reduceToWhileTrueLoop(CFGNode* node);
	void reduceToNestedWhileTrueLoopWithContinueInHeader(
		CFGNode* node, std::size_t succ);
	void structureByGotos(CFGNode* cfg);
	/// @}

	/// @name Condition refinement
	/// @{
	Statement* getIfClauseBody(CFGNode* node,
		CFGNode* clause, CFGNode* ifSuccessor);
	Statement* getIfClauseBodyClone(CFGNode* node,
		CFGNode* clause, CFGNode* ifSuccessor);
	IfStmt* getIfStmt(Expression* cond,
		Statement* trueBody,
		Statement* falseBody = nullptr) const;
	/// @}

	/// @name Loop refinement
	/// @{
	CFGNode* getLoopSuccessor(CFGNode* loopNode) const;
	void completelyReduceLoop(CFGNode* loopNode);
	/// @}

	/// @name Switch refinement
	/// @{
	void reduceSwitchStatement(CFGNode* node);
	CFGNode* getSwitchSuccessor(CFGNode* switchNode) const;
	bool isNodeAfterAllSwitchClauses(CFGNode* node,
		CFGNode* switchNode) const;
	bool isNodeAfterSwitchClause(CFGNode* node,
		CFGNode* clauseNode) const;
	bool hasDefaultClause(CFGNode* switchNode,
		CFGNode* switchSuccessor) const;
	bool isReducibleClause(CFGNode* clauseNode,
		CFGNode* switchNode,
		CFGNode* switchSuccessor,
		bool hasDefault = true) const;
	bool hasOnlySwitchOrClausesInPreds(CFGNode* clauseNode,
		CFGNode* switchNode, bool hasDefault) const;
	bool fallsThroughToAnotherCase(CFGNode* clauseNode,
		CFGNode* switchNode, bool hasDefault) const;
	SwitchStmt* getSwitchStmt(CFGNode* switchNode,
		CFGNode* switchSuccessor, bool hasDefault);
	SwitchClauseVector getSwitchClauses(CFGNode* switchNode,
		bool hasDefault) const;
	SwitchClauseVector sortSwitchClauses(const SwitchClauseVector &clauses,
		CFGNode* switchSuccessor) const;
	SwitchClause* findFirstClauseWithSinglePred(
		const SwitchClauseVector &clauses) const;
	Statement* getClauseBody(CFGNode* clauseNode,
		CFGNode* switchNode,
		CFGNode* switchSuccessor,
		CFGNode::CFGNodeSet &generated);
	bool isClauseTerminatedByBreak(CFGNode* clauseNode,
		CFGNode* switchSuccessor) const;
	void addClausesWithTheSameCond(SwitchStmt* switchStmt,
		const ExprVector &conds, Statement* clauseBody) const;
	void removeReducedSuccsOfSwitch(CFGNode* switchNode,
		bool hasDefault) const;
	/// @}

	/// @name Successor getters
	/// @{
	Statement* getSuccessorsBody(CFGNode* node,
		CFGNode* succ);
	Statement* getSuccessorsBodyClone(CFGNode* node,
		CFGNode* succ);
	Statement* getGotoForSuccessor(CFGNode* node,
		CFGNode* target);
	Statement* getAssignsToPHINodes(CFGNode* from,
		CFGNode* to);
	Statement* getPHICopiesForSuccessor(llvm::BasicBlock *currBB,
		llvm::BasicBlock *succ);
	/// @}

	/// @name Work with LLVM analyses
	/// @{
	void initialiazeLLVMAnalyses(llvm::Function &func);
	llvm::Loop *getLoopFor(CFGNode* node) const;
	bool isLoopHeader(CFGNode* node) const;
	bool isLoopHeader(CFGNode* node, llvm::Loop *loop) const;
	bool isNodeOutsideLoop(CFGNode* node, llvm::Loop *loop) const;
	bool isInParentLoopOf(CFGNode* node, llvm::Loop *loop) const;
	unsigned getTripCount(llvm::Loop *loop) const;
	bool canBeForLoop(llvm::Loop *loop) const;
	/// @}

	/// @name Postprocessing methods
	/// @{
	Statement* replaceBreakOrContinueOutsideLoop(
		Statement* statement, SwitchParent sp);
	void replaceGoto(CFGNodeVector &targets);
	void correctUndefinedLabels();
	std::vector<Statement*> findContinueOrBreakStatements(
		Statement* parent, SwitchParent sp);
	unsigned getStatementCount(Statement* statement);
	void insertClonedLoopTargets( Statement* origParent,
		Statement* newParent);
	void fixClonedGotos(Statement* statement);
	/// @}

	/// @name Helper methods
	/// @{
	void addGotoTargetIfNotExists(CFGNode* node);
	void addBranchMetadataToEndOfBodyIfNeeded(Statement* body,
		CFGNode* clause, CFGNode* ifSuccessor) const;
	std::string getLabel(CFGNode* node) const;
	void cleanUp();
	/// @}

	/// Pass that have instantiated the converter.
	llvm::Pass *basePass = nullptr;

	/// Information about loops.
	llvm::LoopInfo *loopInfo = nullptr;

	// Anylysis of scalar expressions in loops.
	llvm::ScalarEvolution *scalarEvolution = nullptr;

	/// A handler of labels.
	LabelsHandler* labelsHandler = nullptr;

	/// A converter of the LLVM basic block.
	BasicBlockConverter bbConverter;

	/// A converter from LLVM values to values in BIR.
	LLVMValueConverter* converter = nullptr;

	/// A map of the corresponding loops and loop headers represented
	/// by CFG nodes.
	MapLoopToCFGNode loopHeaders;

	/// A map of already generated phi nodes from specific basic blocks.
	MapBBToBBSet generatedPHINodes;

	/// A map of targets for break and continue statements
	MapStmtToTargetNode loopTargets;

	/// A map of goto target statements to cfg nodes.
	MapStmtToTargetNode gotoTargetsToCfgNodes;

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

	/// The resulting module in BIR.
	Module* resModule = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
