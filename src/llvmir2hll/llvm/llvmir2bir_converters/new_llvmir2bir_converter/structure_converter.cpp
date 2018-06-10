/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/structure_converter.cpp
* @brief Implementation of StructureConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/basic_block_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/structure_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using namespace std::placeholders;

using retdec::utils::hasItem;
using retdec::utils::removeItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Size of integral value (in bits) for some constants in @c for loops, e.g.
/// step or start value. It was chosen to use 32 bits because it is enough
/// also for huge number of iterations.
const unsigned FOR_CONST_SIZE_BITS = 32;

/// Number of statement which is accepted tob be cloned.
const unsigned LIMIT_CLONED_STATEMENTS = 5;

/// Minimal number of statements in goto target appended to the end of functions
/// if target body has less statements, it is inserted in place of goto statement
const unsigned MIN_GOTO_STATEMENTS = 3;

} // anonymous namespace

/**
* @brief Constructs a new structure converter.
*
* @param[in] basePass Pass that have instantiated the converter.
* @param[in] conv A converter from LLVM values to values in BIR.
*/
StructureConverter::StructureConverter(llvm::Pass *basePass,
	ShPtr<LLVMValueConverter> conv):
		basePass(basePass), loopInfo(), scalarEvolution(),
		labelsHandler(std::make_shared<LabelsHandler>()),
		bbConverter(std::make_unique<BasicBlockConverter>(conv, labelsHandler)),
		converter(conv), loopHeaders(), generatedPHINodes(),
		reducedLoops(), reducedSwitches() {}

/**
* @brief Destructs the converter.
*/
StructureConverter::~StructureConverter() {}

/**
* @brief Converts body of the given LLVM function @a func into a sequence
*        of statements in BIR which include conditional statements and loops.
*
* @par Preconditions
*  - @a func is not a function declaration
*/
ShPtr<Statement> StructureConverter::convertFuncBody(llvm::Function &func) {
	PRECONDITION(!func.isDeclaration(), "func cannot be a declaration");

	initialiazeLLVMAnalyses(func);
	auto cfg = createCFG(func.getEntryBlock());
	detectBackEdges(cfg);

	while (cfg->getSuccNum() != 0 && reduceCFG(cfg)) {
		// Keep looping until the CFG is reduced.
	}

	if (cfg->getSuccNum() != 0) {
		structureByGotos(cfg);
	}

	if (!gotoTargets.empty()) {
		CFGNodeVector gotoTargetsCopy(gotoTargets);
		for (const auto &node: gotoTargetsCopy) {
			if (!hasItem(generatedNodes, node)) {
				structureByGotos(node);
			}
		}

		replaceGoto(gotoTargets);

		for (const auto &node: gotoTargets) {
			if (!hasItem(generatedNodes, node)) {
				cfg->appendToBody(replaceBreakOrContinueOutsideLoop(node->getBody(),
					SwitchParent::No));
				generatedNodes.insert(node);
			}
		}
	}

	correctUndefinedLabels();

	cleanUp();
	return cfg->getBody();
}

/**
* @brief Deep clone statements
*/
ShPtr<Statement> StructureConverter::deepCloneStatements(ShPtr<Statement> orig) {
	ShPtr<Statement> currStmt = orig;
	ShPtr<Statement> clonedStmts;

	while (currStmt) {
		auto currStmtClone = ucast<Statement>(currStmt->clone());

		if (auto ifStmt = cast<IfStmt>(currStmt)) {
			auto cloneIfStmt = cast<IfStmt>(currStmtClone);
			// only if/else here (no else if)
			cloneIfStmt->setFirstIfBody(deepCloneStatements(ifStmt->getFirstIfBody()));
			if (cloneIfStmt->hasElseClause()) {
				cloneIfStmt->setElseClause(deepCloneStatements(ifStmt->getElseClause()));
			}
		} else if (auto switchStmt = cast<SwitchStmt>(currStmt)) {
			auto cloneSwitchStmt = cast<SwitchStmt>(currStmtClone);
			auto cloneClause = cloneSwitchStmt->clause_begin();
			for (auto clause = switchStmt->clause_begin();
					clause != switchStmt->clause_end(); ++clause) {

				Statement::replaceStatement(cloneClause->second, deepCloneStatements(clause->second));
				++cloneClause;
			}
		} else if (auto whileStmt = cast<WhileLoopStmt>(currStmt)) {
			auto cloneWhileStmt = cast<WhileLoopStmt>(currStmtClone);
			cloneWhileStmt->setBody(deepCloneStatements(whileStmt->getBody()));
		}

		clonedStmts = Statement::mergeStatements(clonedStmts, currStmtClone);
		currStmt = currStmt->getSuccessor();
	}

	return clonedStmts;
}

/**
* @brief Replaces goto with code if there is only one reference to it
*/
void StructureConverter::replaceGoto(CFGNodeVector &targets) {
	for (const auto &target : targets) {
		if (!hasItem(generatedNodes, target)) {
			auto targetBody = target->getBody();
			auto predNum = targetBody->getNumberOfPredecessors();
			if (predNum == 0) {
				// has zero references, delete it
				Statement::removeStatement(targetBody);
				generatedNodes.insert(target);
			} else if (predNum == 1) {
				//ShPtr<Statement> targetBodyClone = deepCloneStatements(targetBody);
				ShPtr<Statement> targetBodyClone = Statement::cloneStatements(targetBody);
				if (getStatementCount(targetBodyClone) != getStatementCount(targetBody)) {
					continue;
				}
				// has one reference, replace goto with body of label
				for (auto pred = targetBody->predecessor_begin();
						pred != targetBody->predecessor_end(); ++pred) {

					ShPtr<GotoStmt> stmt = cast<GotoStmt>(*pred);
					if (stmt && stmt->getTarget() == targetBody) {
						insertClonedLoopTargets(targetBody, targetBodyClone);
						Statement::replaceStatement(stmt, targetBodyClone);
						generatedNodes.insert(target);
						break;
					}
				}
			} else {
				// check if body of label has "enough" statements
				auto stmt = targetBody;
				unsigned cnt = 0;
				while (stmt) {
					if (stmt->isCompound()) {
						cnt = MIN_GOTO_STATEMENTS + 1;
						break;
					}
					if (++cnt > MIN_GOTO_STATEMENTS) {
						break;
					}
					stmt = stmt->getSuccessor();
				}
				if (cnt <= MIN_GOTO_STATEMENTS) {
					// contains just a few statements
					//ShPtr<Statement> targetBodyClone = deepCloneStatements(targetBody);
					ShPtr<Statement> targetBodyClone = Statement::cloneStatements(targetBody);
					if (getStatementCount(targetBodyClone) != getStatementCount(targetBody)) {
						continue;
					}
					std::vector<ShPtr<Statement>> toReplace;
					for (auto pred = targetBody->predecessor_begin();
							pred != targetBody->predecessor_end(); ++pred) {

						ShPtr<GotoStmt> stmt = cast<GotoStmt>(*pred);
						if (stmt && stmt->getTarget() == targetBody) {
							toReplace.push_back(stmt);
						}
					}
					// replacing needs to be done later (it changes predecessors)
					for (auto &stmt : toReplace) {
						if (stmt != toReplace.front()) {
							//targetBodyClone = deepCloneStatements(targetBody);
							targetBodyClone = Statement::cloneStatements(targetBody);
						}
						insertClonedLoopTargets(targetBody, targetBodyClone);
						Statement::replaceStatement(stmt, targetBodyClone);
					}
					generatedNodes.insert(target);
				}
			}
		}
	}
}

/**
* @brief Returns number of statements in parent statement (body of if/while etc.)
*/
unsigned StructureConverter::getStatementCount(ShPtr<Statement> statement) {
	ShPtr<Statement> stmt = statement;
	unsigned cnt = 0;
	while (stmt) {
		if (auto ifStmt = cast<IfStmt>(stmt)) {
			cnt += getStatementCount(ifStmt->getFirstIfBody());
			cnt += getStatementCount(ifStmt->getElseClause());
		} else if (auto switchStmt = cast<SwitchStmt>(stmt)) {
			for (auto clause = switchStmt->clause_begin();
					clause != switchStmt->clause_end(); ++clause) {

				cnt += getStatementCount((*clause).second);
			}
		} else if (auto whileStmt = cast<WhileLoopStmt>(stmt)) {
			cnt += getStatementCount(whileStmt->getBody());
		} else {
			cnt++;
		}
		stmt = stmt->getSuccessor();
	}
	return cnt;
}

/**
* @brief If goto target label is not used in code, it is replaced
*   with its clone (that is used)
*/
void StructureConverter::correctUndefinedLabels() {
	for (auto &label : targetReferences) {
		auto targetBody = label.first->getBody();
		auto it = stmtClones.find(targetBody);
		if (it != stmtClones.end()) {
			for (auto &ref : label.second) {
				if (auto gotoRef = cast<GotoStmt>(ref)) {
					gotoRef->setTarget(it->second.back());
					it->second.back()->setLabel(targetBody->getLabel());
				}
			}
		}
	}
}

/**
* @brief Replaces break/continue statements that are outside of loop with goto statements
*/
ShPtr<Statement> StructureConverter::replaceBreakOrContinueOutsideLoop(ShPtr<Statement> statement,
		SwitchParent sp) {

	ShPtr<Statement> stmt = statement;
	while (stmt) {
		// go only into IfStmt and SwitchStmt (no need to replace inside loop)
		if (auto ifStmt = cast<IfStmt>(stmt)) {
			replaceBreakOrContinueOutsideLoop(ifStmt->getFirstIfBody(), sp);
			replaceBreakOrContinueOutsideLoop(ifStmt->getElseClause(), sp);
		} else if (auto switchStmt = cast<SwitchStmt>(stmt)) {
			for (auto clause = switchStmt->clause_begin();
					clause != switchStmt->clause_end(); ++clause) {

				replaceBreakOrContinueOutsideLoop((*clause).second, SwitchParent::Yes);
			}
		} else {
			if ((isa<BreakStmt>(stmt) && sp != SwitchParent::Yes) || isa<ContinueStmt>(stmt)) {
				auto it = loopTargets.find(stmt);
				if (it != loopTargets.end()) {
					labelsHandler->setGotoTargetLabel(it->second->getBody(), it->second->getFirstBB());
					ShPtr<Statement> gotoStmt = GotoStmt::create(it->second->getBody());
					if (isa<ContinueStmt>(stmt)) {
						gotoStmt->setMetadata("continue -> " + getLabel(it->second));
					} else {
						gotoStmt->setMetadata("break -> " + getLabel(it->second));
					}
					Statement::replaceStatement(it->first, gotoStmt);
				}
			}
		}
		stmt = stmt->getSuccessor();
	}
	return statement;
}

/**
* @brief Creates control-flow graph of the function from the given root basic
*        block @a root.
*/
ShPtr<CFGNode> StructureConverter::createCFG(llvm::BasicBlock &root) const {
	auto cfg = std::make_shared<CFGNode>(&root, bbConverter->convert(root));
	CFGNodeQueue toBeVisited({cfg});
	MapBBToCFGNode visited{
		{&root, cfg}
	};

	while (!toBeVisited.empty()) {
		auto node = popFromQueue(toBeVisited);

		auto terminator = node->getTerm();
		auto successorsNum = terminator->getNumSuccessors();
		for (decltype(successorsNum) i = 0; i < successorsNum; ++i) {
			ShPtr<CFGNode> nextNode;

			auto succ = terminator->getSuccessor(i);
			auto existingNodeIt = visited.find(succ);
			if (existingNodeIt == visited.end()) {
				auto body = bbConverter->convert(*succ);
				nextNode = std::make_shared<CFGNode>(succ, body);
				toBeVisited.push(nextNode);
				visited.emplace(succ, nextNode);
			} else {
				nextNode = existingNodeIt->second;
			}

			node->addSuccessor(nextNode);
		}
	}

	return cfg;
}

/**
* @brief Traverses the given control-flow graph @a cfg and detects all back edges.
*
* @par Preconditions
*  - @a cfg is non-null
*/
void StructureConverter::detectBackEdges(ShPtr<CFGNode> cfg) const {
	PRECONDITION_NON_NULL(cfg);

	CFGNodeStack toBeVisited({cfg});
	MapCFGNodeToDFSNodeState visitedNodeStates;
	while (!toBeVisited.empty()) {
		auto node = toBeVisited.top();
		auto currNodeMapIt = visitedNodeStates.find(node);
		if (currNodeMapIt == visitedNodeStates.end()) {
			visitedNodeStates.emplace(node, DFSNodeState::Opened);

			for (auto i = node->getSuccNum(); i-- > 0;) {
				auto nextNode = node->getSucc(i);
				auto nextNodeMapIt = visitedNodeStates.find(nextNode);
				if (nextNodeMapIt == visitedNodeStates.end()) {
					toBeVisited.push(nextNode);
				} else if (nextNodeMapIt->second == DFSNodeState::Opened) {
					node->markAsBackEdge(nextNode);
				}
			}
		} else {
			currNodeMapIt->second = DFSNodeState::Closed;
			toBeVisited.pop();
		}
	}
}

/**
* @brief Traverses the given control-flow graph @a cfg and tries to reduce some
*        nodes to control-flow statements.
*
* @returns Returns @c true if any node have been reduced.
*
* @par Preconditions
*  - @a cfg is non-null
*/
bool StructureConverter::reduceCFG(ShPtr<CFGNode> cfg) {
	PRECONDITION_NON_NULL(cfg);

	return BFSTraverse(cfg, [this](const auto &node) {
		return this->inspectCFGNode(node);
	});
}

/**
* @brief Inspects the given CFG node @a node and tries to reduce this and
*        neighboring nodes to any control-flow statement.
*
* @returns Returns @c true if the node have been reduced.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::inspectCFGNode(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	if (isLoopHeader(node) && !hasItem(statementsOnStack, node) &&
			(statementsStack.empty() || statementsStack.top() != node)) {
		loopHeaders.emplace(getLoopFor(node), node);
		node->setStatementSuccessor(getLoopSuccessor(node));

		statementsStack.push(node);
		statementsOnStack.insert(node);
		completelyReduceLoop(node);
		statementsStack.pop();
		statementsOnStack.erase(node);
		return true;
	}

	if (isSequence(node)) {
		reduceToSequence(node);
		return true;
	} else if (isForLoop(node)) {
		reduceToForLoop(node);
		return true;
	} else if (isWhileTrueLoop(node)) {
		reduceToWhileTrueLoop(node);
		return true;
	} else if (isNestedWhileTrueLoopWithContinueInHeader(node, 0)) {
		reduceToNestedWhileTrueLoopWithContinueInHeader(node, 0);
		return true;
	} else if (isNestedWhileTrueLoopWithContinueInHeader(node, 1)) {
		reduceToNestedWhileTrueLoopWithContinueInHeader(node, 1);
		return true;
	} else if (isSwitchStatement(node)) {
		reduceSwitchStatement(node);
		return true;
	} else if (isIfElseStatement(node)) {
		reduceToIfElseStatement(node);
		return true;
	} else if (isIfStatement(node, 0) || isIfStatementWithTerminatingBranch(node, 0)) {
		reduceToIfStatement(node, 0);
		return true;
	} else if (isIfStatement(node, 1) || isIfStatementWithTerminatingBranch(node, 1)) {
		reduceToIfStatement(node, 1);
		return true;
	} else if (isIfStatementWithBreakInLoop(node, 0)) {
		reduceToIfElseStatementWithBreakInLoop(node, 0);
		return true;
	} else if (isIfStatementWithBreakInLoop(node, 1)) {
		reduceToIfElseStatementWithBreakInLoop(node, 1);
		return true;
	} else if (isIfElseStatementWithContinue(node, 0)) {
		reduceToIfElseStatementWithContinue(node, 0);
		return true;
	} else if (isIfElseStatementWithContinue(node, 1)) {
		reduceToIfElseStatementWithContinue(node, 1);
		return true;
	} else if(isContinueStatement(node)) {
		reduceToContinueStatement(node);
		return true;
	} else if (isIfStatementWithTerminatingBranchToClone(node, 0)) {
		reduceToIfStatementClone(node, 0);
		return true;
	} else if (isIfStatementWithTerminatingBranchToClone(node, 1)) {
		reduceToIfStatementClone(node, 1);
		return true;
	} else if (isSequenceWithTerminatingBranchToClone(node)) {
		reduceToSequenceClone(node);
		return true;
	} else if (isIfStatementWithBreakByGotoInLoop(node, 0)) {
		reduceToIfElseStatementWithBreakByGotoInLoop(node, 0);
		return true;
	} else if (isIfStatementWithBreakByGotoInLoop(node, 1)) {
		reduceToIfElseStatementWithBreakByGotoInLoop(node, 1);
		return true;
	}

	return false;
}

/**
* @brief Pop and return node from the given queue @a queue.
*/
ShPtr<CFGNode> StructureConverter::popFromQueue(CFGNodeQueue &queue) const {
	PRECONDITION(!queue.empty(), "queue is empty");

	auto element = queue.front();
	queue.pop();
	return element;
}

/**
* @brief Adds all unvisited successors of the given node @a node to the queue
*        @a toBeVisited and also to the set of visited nodes @a visited.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::addUnvisitedSuccessorsToQueue(const ShPtr<CFGNode> &node,
		CFGNodeQueue &toBeVisited, CFGNode::CFGNodeSet &visited) const {
	PRECONDITION_NON_NULL(node);

	for (const auto &nextNode: node->getSuccessors()) {
		if (!hasItem(visited, nextNode) && !node->isBackEdge(nextNode)) {
			toBeVisited.push(nextNode);
			visited.insert(nextNode);
		}
	}

	if (node->hasStatementSuccessor()) {
		auto statementSucc = node->getStatementSuccessor();
		if (!hasItem(visited, statementSucc)
				&& !node->isBackEdge(statementSucc)) {
			toBeVisited.push(statementSucc);
			visited.insert(statementSucc);
		}
	}
}

/**
* @brief Adds all unvisited successors inside loop @a loop of the given node
*        @a node to the queue @a toBeVisited and also to the set of visited
*        nodes @a visited.
*
* @par Preconditions
*  - @a node is non-null
*  - @a loop is non-null
*/
void StructureConverter::addUnvisitedSuccessorsToQueueInLoop(const ShPtr<CFGNode> &node,
		CFGNodeQueue &toBeVisited, CFGNode::CFGNodeSet &visited,
		llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(loop);

	for (const auto &nextNode: node->getSuccessors()) {
		if (!hasItem(visited, nextNode) && !node->isBackEdge(nextNode)) {
			if (isNodeOutsideLoop(nextNode, loop)) {
				continue;
			}

			toBeVisited.push(nextNode);
			visited.insert(nextNode);
		}
	}
}

/**
* @brief Traverses the given control-flow graph @a cfg using breadth-first
*        search and inspect every node by function @a inspectFunc.
*
* @returns Returns @c true if inspection of any node return @c true.
*
* @par Preconditions
*  - @a cfg is non-null
*/
bool StructureConverter::BFSTraverse(ShPtr<CFGNode> cfg,
		std::function<bool (ShPtr<CFGNode>)> inspectFunc) const {
	PRECONDITION_NON_NULL(cfg);

	bool anyTrueResult = false;
	CFGNodeQueue toBeVisited({cfg});
	CFGNode::CFGNodeSet visited{cfg};
	while (!toBeVisited.empty()) {
		auto node = popFromQueue(toBeVisited);
		if (inspectFunc(node)) {
			anyTrueResult = true;
		}

		addUnvisitedSuccessorsToQueue(node, toBeVisited, visited);
	}

	return anyTrueResult;
}

/**
* @brief Traverses the given control-flow graph @a cfg of a loop using
*        breadth-first search and inspect every node by function @a inspectFunc.
*
* @returns Returns @c true if inspection of any node return @c true.
*
* @par Preconditions
*  - @a cfg is non-null
*/
bool StructureConverter::BFSTraverseLoop(ShPtr<CFGNode> cfg,
		std::function<bool (ShPtr<CFGNode>)> inspectFunc) const {
	PRECONDITION_NON_NULL(cfg);

	auto loop = getLoopFor(cfg);
	bool anyTrueResult = false;
	CFGNodeQueue toBeVisited({cfg});
	CFGNode::CFGNodeSet visited{cfg};
	while (!toBeVisited.empty()) {
		auto node = popFromQueue(toBeVisited);
		if (inspectFunc(node)) {
			anyTrueResult = true;
		}

		addUnvisitedSuccessorsToQueueInLoop(node, toBeVisited, visited, loop);
	}

	return anyTrueResult;
}

/**
* @brief Traverses the given control-flow graph @a cfg using breadth-first
*        search and returns first node which satisfies the predicate @a pred.
*
* @par Preconditions
*  - @a cfg is non-null
*/
ShPtr<CFGNode> StructureConverter::BFSFindFirst(ShPtr<CFGNode> cfg,
		std::function<bool (ShPtr<CFGNode>)> pred) const {
	PRECONDITION_NON_NULL(cfg);

	CFGNodeQueue toBeVisited({cfg});
	CFGNode::CFGNodeSet visited{cfg};
	while (!toBeVisited.empty()) {
		auto node = popFromQueue(toBeVisited);
		if (pred(node)) {
			return node;
		}

		addUnvisitedSuccessorsToQueue(node, toBeVisited, visited);
	}

	return nullptr;
}

/**
* @brief Determines whether exists direct path (without loops) between two given
*        nodes @a node1 and @a node2.
*
* @par Preconditions
*  - both @a node1 and @a node2 are non-null
*/
bool StructureConverter::existsPathWithoutLoopsBetween(const ShPtr<CFGNode> &node1,
		const ShPtr<CFGNode> &node2) const {
	PRECONDITION_NON_NULL(node1);
	PRECONDITION_NON_NULL(node2);

	auto predicate = [&node2](const auto &node) {
		return node == node2;
	};

	return BFSFindFirst(node1, predicate) != nullptr;
}

/**
* @brief Determines whether the given node @a node can be reduced with following
*        node as a sequence.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isSequence(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	return node->getSuccNum() == 1 &&
		node->getSucc(0)->getPredsNum() == 1 &&
		node->getSucc(0) != node;
}

/**
* @brief Determines whether the given node @a node can be reduced with following
*        node as a sequence, where is cloned the terminating successor.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isSequenceWithTerminatingBranchToClone(
		const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	if (node->getSuccNum() != 1) {
		return false;
	}

	auto succNode = node->getSucc(0);
	return succNode->getSuccNum() == 0 && canBeCloned(succNode) &&
		succNode != node;
}

/**
* @brief Determines whether the given the given node @a node is an if statement
*        with else clause.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isIfElseStatement(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	return node->getSuccNum() == 2
		&& node->getSucc(0)->getSuccNum() == 1 && node->getSucc(0)->getPredsNum() == 1
		&& node->getSucc(1)->getSuccNum() == 1 && node->getSucc(1)->getPredsNum() == 1
		&& node->getSucc(0)->getSucc(0) == node->getSucc(1)->getSucc(0);
}

/**
* @brief Determines whether the given node @a node is an if statement without
*        else clause and if body is in the successor on index @a succ.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isIfStatement(const ShPtr<CFGNode> &node,
		std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	std::size_t otherSucc = 1 - succ;
	return node->getSuccNum() == 2
		&& node->getSucc(succ)->getSuccNum() == 1
		&& node->getSucc(succ)->getPredsNum() == 1
		&& node->getSucc(succ)->getSucc(0) == node->getSucc(otherSucc);
}

/**
* @brief Determines whether the given node @a node is an if statement and
*        successor on the index @a succ is terminated (e.g. by return).
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isIfStatementWithTerminatingBranch(
		const ShPtr<CFGNode> &node, std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	if (node->getSuccNum() != 2) {
		return false;
	}

	auto succNode = node->getSucc(succ);
	auto loop = getLoopFor(node);
	if (loop) {
		auto loopNode = loopHeaders.at(loop);
		if (loopNode->getStatementSuccessor() == succNode) {
			return false;
		}
	}

	return succNode->getSuccNum() == 0 && succNode->getPredsNum() == 1;
}

/**
* @brief Determines whether the given node @a node is an if statement and
*        successor on the index @a succ is terminated (e.g. by return).
*
* In comparation to method isIfStatementWithTerminatingBranch(), in this
* case cannot body of the terminating node be already reduced and in usage,
* body must be cloned.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isIfStatementWithTerminatingBranchToClone(
		const ShPtr<CFGNode> &node, std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	if (node->getSuccNum() != 2) {
		return false;
	}

	auto succNode = node->getSucc(succ);
	return succNode->getSuccNum() == 0 && canBeCloned(succNode);
}

/**
* @brief Determines whether the given node @a node is an if statement without
*        else clause and in its successor on the index @a succ schould be break.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isIfStatementWithBreakInLoop(
		const ShPtr<CFGNode> &node, std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto loop = getLoopFor(node);
	if (!loop) {
		return false;
	}

	if (node->getSuccNum() != 2) {
		return false;
	}

	auto nodeSucc = node->getSucc(succ);
	for (auto loopIt = loop; loopIt; loopIt = loopIt->getParentLoop()) {
		auto loopSucc = loopHeaders.at(loopIt)->getStatementSuccessor();
		if (nodeSucc == loopSucc) {
			return true;
		}
	}

	return false;
}

/**
* @brief Determines whether the given node @a node is an if statement without
*        else clause and in its successor on the index @a succ is outside loop.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isIfStatementWithBreakByGotoInLoop(
		const ShPtr<CFGNode> &node, std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto loop = getLoopFor(node);
	if (!loop) {
		return false;
	}

	if (node->getSuccNum() != 2) {
		return false;
	}

	auto nodeSucc = node->getSucc(succ);
	for (auto loopIt = loop; loopIt; loopIt = loopIt->getParentLoop()) {
		if (isLoopHeader(nodeSucc, loopIt)) {
			return false;
		}
	}

	return isNodeOutsideLoop(nodeSucc, loop);
}

/**
* @brief Determines whether the given node @a node is an if statement without
*        else clause and in its successor on the index @a succ schould be continue.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isIfElseStatementWithContinue(const ShPtr<CFGNode> &node,
		std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto loop = getLoopFor(node);
	if (!loop) {
		return false;
	}

	if (node->getSuccNum() != 2) {
		return false;
	}

	auto nodeSucc = node->getSucc(succ);
	if (nodeSucc->getPredsNum() <= 2) {
		return false;
	}

	for (auto loopIt = loop; loopIt; loopIt = loopIt->getParentLoop()) {
		if (isLoopHeader(nodeSucc, loopIt)) {
			return true;
		}
	}

	return false;
}

/**
* @brief Determines whether the given node @a node is terminated by continue
*        statement.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isContinueStatement(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	auto loop = getLoopFor(node);
	if (!loop) {
		return false;
	}

	if (node->getSuccNum() != 1) {
		return false;
	}

	auto nodeSucc = node->getSucc(0);
	if (nodeSucc->getPredsNum() <= 2) {
		return false;
	}

	for (auto loopIt = loop; loopIt; loopIt = loopIt->getParentLoop()) {
		if (isLoopHeader(nodeSucc, loopIt)) {
			return true;
		}
	}

	return false;
}

/**
* @brief Determines whether the given node @a node is a reducible @c for loop.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isForLoop(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	auto loop = getLoopFor(node);
	if (!loop) {
		return false;
	}

	return node->getSuccNum() == 1 && node->getSucc(0) == node
		&& canBeForLoop(loop);
}

/**
* @brief Determines whether the given node @a node is a while(true) loop.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isWhileTrueLoop(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	return node->getSuccNum() == 1 && node->getSucc(0) == node;
}

/**
* @brief Determines whether the given node @a node is a while(true) statement,
*        when on the index @a succ is the body of the loop and on the other
*        index is @c continue statement to the parent loop.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
bool StructureConverter::isNestedWhileTrueLoopWithContinueInHeader(
		const ShPtr<CFGNode> &node, std::size_t succ) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto loop = getLoopFor(node);
	if (!loop) {
		return false;
	}

	if (node->getSuccNum() != 2) {
		return false;
	}

	auto parentLoop = loop->getParentLoop();
	if (!parentLoop || node->getSucc(1 - succ) != loopHeaders.at(parentLoop)) {
		return false;
	}

	return node->getSucc(succ)->getSuccNum() == 1
		&& node->getSucc(succ)->getSucc(0) == node
		&& !node->hasStatementSuccessor()
		&& !node->isBackEdge(node->getSucc(succ));
}

/**
* @brief Determines whether the given node @a node is a switch statement.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isSwitchStatement(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	auto switchInst = llvm::dyn_cast<llvm::SwitchInst>(node->getTerm());
	if (!switchInst || hasItem(reducedSwitches, node->getLastBB())) {
		return false;
	}

	if (node->getSuccNum() == 0) {
		return false;
	}

	auto switchSucc = getSwitchSuccessor(node);
	auto hasDefault = hasDefaultClause(node, switchSucc);

	for (const auto &caseIt: switchInst->cases()) {
		auto index = caseIt.getSuccessorIndex();
		if (node->getSuccNum() <= index) {
			return false;
		}

		auto succ = node->getSucc(index);
		if (!isReducibleClause(succ, node, switchSucc, hasDefault)) {
			return false;
		}
	}

	if (hasDefault && !isReducibleClause(node->getSucc(0), node, switchSucc)) {
		return false;
	}

	return true;
}

/**
* @brief Determines whether the given node @a node can be cloned.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::canBeCloned(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	if (node->getPredsNum() < 2 || node->getPredsNum() == 1) {
		return false;
	}

	auto stmtIt = node->getBody();
	for (unsigned i = 0; i < LIMIT_CLONED_STATEMENTS; ++i) {
		if (stmtIt->isCompound()) {
			return false;
		} else if (!stmtIt->hasSuccessor()) {
			return true;
		}

		stmtIt = stmtIt->getSuccessor();
	}

	return false;
}

/**
* @brief Reduces node @a node and its only successor into a single node which
*        contains merged bodies of both nodes.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceToSequence(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	auto succ = node->getSucc(0);
	node->appendToBody(getSuccessorsBody(node, succ));
	node->setLastBB(succ->getLastBB());
	node->moveSuccessorsFrom(succ);
	generatedNodes.insert(succ);
}

/**
* @brief Reduces node @a node and its only successor into a single node which
*        contains merged bodies of both nodes, where is cloned the terminating
*        successor.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceToSequenceClone(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	auto succ = node->getSucc(0);
	node->appendToBody(getSuccessorsBodyClone(node, succ));
	node->setLastBB(succ->getLastBB());
	node->removeSucc(0);
	generatedNodes.insert(succ);
}

/**
* @brief Reduces node @a node and both its successors into a single node with
*        if statement with else clause.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceToIfElseStatement(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	generatedNodes.insert(node->getSucc(0));
	generatedNodes.insert(node->getSucc(1));

	auto cond = converter->convertValueToExpression(node->getCond());
	auto newSucc = node->getSucc(0)->getSucc(0);
	auto trueBody = getIfClauseBody(node, node->getSucc(0), newSucc);
	auto falseBody = getIfClauseBody(node, node->getSucc(1), newSucc);
	node->appendToBody(getIfStmt(cond, trueBody, falseBody));

	node->deleteSuccessors();
	node->addSuccessor(newSucc);
}

/**
* @brief Reduces node @a node and its successor on index @a succ into a single
*        node with if statement without else clause.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
void StructureConverter::reduceToIfStatement(ShPtr<CFGNode> node,
		std::size_t succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	generatedNodes.insert(node->getSucc(succ));

	auto cond = converter->convertValueToExpression(node->getCond());
	if (succ == 1) {
		cond = ExpressionNegater::negate(cond);
	}

	auto newSucc = node->getSucc(1 - succ);
	auto trueBody = getIfClauseBody(node, node->getSucc(succ), newSucc);
	auto falseBody = getAssignsToPHINodes(node, newSucc);
	node->appendToBody(getIfStmt(cond, trueBody, falseBody));

	node->deleteSucc(succ);
}

/**
* @brief Reduces node @a node and its successor on index @a succ into a single
*        node with if statement without else clause. The body of the node on
*        index @a succ is cloned.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
void StructureConverter::reduceToIfStatementClone(ShPtr<CFGNode> node,
		std::size_t succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	generatedNodes.insert(node->getSucc(succ));

	auto cond = converter->convertValueToExpression(node->getCond());
	if (succ == 1) {
		cond = ExpressionNegater::negate(cond);
	}

	auto succNode = node->getSucc(succ);
	auto newSucc = node->getSucc(1 - succ);
	auto trueBody = getIfClauseBodyClone(node, succNode, newSucc);
	auto falseBody = getAssignsToPHINodes(node, newSucc);
	node->appendToBody(getIfStmt(cond, trueBody, falseBody));

	node->removeSucc(succ);
}

/**
* @brief Reduces node @a node and its successor on index @a succ into a single
*        node with if statement with break statement inside.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
void StructureConverter::reduceToIfElseStatementWithBreakInLoop(ShPtr<CFGNode> node,
		std::size_t succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto cond = converter->convertValueToExpression(node->getCond());
	if (succ == 1) {
		cond = ExpressionNegater::negate(cond);
	}

	auto loop = getLoopFor(node);
	auto targetNode = node->getSucc(succ);

	if (!canBeForLoop(loop)) {
		ShPtr<Statement> breakStmt;
		if (targetNode == loopHeaders.at(loop)->getStatementSuccessor()) {
			breakStmt = BreakStmt::create();
			breakStmt->setMetadata("break -> " + getLabel(targetNode));
			loopTargets.emplace(breakStmt, targetNode);
		} else {
			labelsHandler->setGotoTargetLabel(targetNode->getBody(), targetNode->getFirstBB());
			breakStmt = GotoStmt::create(targetNode->getBody());
			breakStmt->setMetadata("break (via goto) -> " + getLabel(targetNode));
			targetReferences[targetNode].push_back(breakStmt);
			addGotoTargetIfNotExists(targetNode);
		}

		auto phiCopies = getAssignsToPHINodes(node, targetNode);
		auto ifBody = Statement::mergeStatements(phiCopies, breakStmt);
		node->appendToBody(getIfStmt(cond, ifBody));
	}

	node->removeSucc(succ);
}

/**
* @brief Reduces node @a node and its successor on index @a succ into a single
*        node with if statement with goto statement inside.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
void StructureConverter::reduceToIfElseStatementWithBreakByGotoInLoop(ShPtr<CFGNode> node,
		std::size_t succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto cond = converter->convertValueToExpression(node->getCond());
	if (succ == 1) {
		cond = ExpressionNegater::negate(cond);
	}

	auto targetNode = node->getSucc(succ);
	auto targetNodeBB = targetNode->getFirstBB();

	auto gotoTarget = targetNode->getBody();
	labelsHandler->setGotoTargetLabel(gotoTarget, targetNodeBB);

	auto phiCopies = getAssignsToPHINodes(node, targetNode);
	auto gotoStmt = GotoStmt::create(gotoTarget);
	targetReferences[targetNode].push_back(gotoStmt);
	auto ifBody = Statement::mergeStatements(phiCopies, gotoStmt);
	node->appendToBody(getIfStmt(cond, ifBody));

	addGotoTargetIfNotExists(targetNode);

	node->removeSucc(succ);
}

/**
* @brief Reduces node @a node and its successor on index @a succ into a single
*        node with if statement with continue statement inside.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
void StructureConverter::reduceToIfElseStatementWithContinue(ShPtr<CFGNode> node,
		std::size_t succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto cond = converter->convertValueToExpression(node->getCond());
	if (succ == 1) {
		cond = ExpressionNegater::negate(cond);
	}

	auto targetNode = node->getSucc(succ);

	ShPtr<Statement> continueStmt;
	if (targetNode == loopHeaders.at(getLoopFor(node))) {
		continueStmt = ContinueStmt::create();
		continueStmt->setMetadata("continue -> " + getLabel(targetNode));
		loopTargets.emplace(continueStmt, targetNode);
	} else {
		labelsHandler->setGotoTargetLabel(targetNode->getBody(), targetNode->getFirstBB());
		continueStmt = GotoStmt::create(targetNode->getBody());
		targetReferences[targetNode].push_back(continueStmt);
		continueStmt->setMetadata("continue (via goto) -> " + getLabel(targetNode));
		addGotoTargetIfNotExists(targetNode);
	}

	auto phiCopies = getAssignsToPHINodes(node, targetNode);
	auto ifBody = Statement::mergeStatements(phiCopies, continueStmt);
	node->appendToBody(getIfStmt(cond, ifBody));

	node->removeSucc(succ);
}

/**
* @brief Reduces node @a node into a node which is terminated by switch statement.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceToContinueStatement(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	auto targetNode = node->getSucc(0);

	ShPtr<Statement> continueStmt;
	if (targetNode == loopHeaders.at(getLoopFor(node))) {
		continueStmt = ContinueStmt::create();
		continueStmt->setMetadata("continue -> " + getLabel(targetNode));
		loopTargets.emplace(continueStmt, targetNode);
	} else {
		labelsHandler->setGotoTargetLabel(targetNode->getBody(), targetNode->getFirstBB());
		continueStmt = GotoStmt::create(targetNode->getBody());
		targetReferences[targetNode].push_back(continueStmt);
		continueStmt->setMetadata("continue (via goto) -> " + getLabel(targetNode));
		addGotoTargetIfNotExists(targetNode);
	}

	node->appendToBody(getAssignsToPHINodes(node, targetNode));
	node->appendToBody(continueStmt);

	node->removeSucc(0);
}

/**
* @brief Reduces node @a node into a node with @c for loop
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceToForLoop(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	auto loop = getLoopFor(node);
	auto indVarPhi = loop->getCanonicalInductionVariable();
	auto indVar = converter->convertValueToVariable(indVarPhi);
	auto tripCount = ConstInt::create(getTripCount(loop), FOR_CONST_SIZE_BITS);
	auto startValue = ConstInt::create(0, FOR_CONST_SIZE_BITS);
	auto endCond = LtOpExpr::create(indVar, tripCount, LtOpExpr::Variant::SCmp);
	auto step = ConstInt::create(1, FOR_CONST_SIZE_BITS);

	node->appendToBody(getAssignsToPHINodes(node, node));

	auto continueStmt = EmptyStmt::create();
	continueStmt->setMetadata("continue -> " + getLabel(node));
	node->appendToBody(continueStmt);

	node->setBody(ForLoopStmt::create(indVar, startValue, endCond, step, node->getBody()));

	node->removeSucc(0);
	reducedLoops.insert(loop);

	if (node->hasStatementSuccessor()) {
		node->addSuccessor(node->getStatementSuccessor());
		node->removeStatementSuccessor();
	}
}

/**
* @brief Reduces node @a node into a node with while(true) loop.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceToWhileTrueLoop(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	node->appendToBody(getAssignsToPHINodes(node, node));

	auto continueStmt = EmptyStmt::create();
	continueStmt->setMetadata("continue -> " + getLabel(node));
	node->appendToBody(continueStmt);

	node->setBody(WhileLoopStmt::create(ConstBool::create(true), node->getBody()));

	node->removeSucc(0);
	reducedLoops.insert(getLoopFor(node));

	if (node->hasStatementSuccessor()) {
		node->addSuccessor(node->getStatementSuccessor());
		node->removeStatementSuccessor();
	}
}

/**
* @brief Reduces the given node @a node is into a while(true) statement,
*        when on the index @a succ is the body of the loop and on the other
*        index is @c continue statement to the parent loop.
*
* @par Preconditions
*  - @a node is non-null
*  - @a succ has value 0 or 1
*/
void StructureConverter::reduceToNestedWhileTrueLoopWithContinueInHeader(
		ShPtr<CFGNode> node, std::size_t succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION(succ == 0 || succ == 1, "succ is not 0 or 1");

	auto cond = converter->convertValueToExpression(node->getCond());
	if (succ == 0) {
		cond = ExpressionNegater::negate(cond);
	}

	auto innerLoop = node->getSucc(succ);
	generatedNodes.insert(innerLoop);
	auto parentLoopHeader = node->getSucc(1 - succ);

	auto phiCopies = getAssignsToPHINodes(node, parentLoopHeader);
	auto breakStmt = BreakStmt::create();
	loopTargets.emplace(breakStmt, parentLoopHeader);
	breakStmt->setMetadata("break -> " + getLabel(parentLoopHeader));

	auto ifBody = Statement::mergeStatements(phiCopies, breakStmt);
	node->appendToBody(getIfStmt(cond, ifBody));

	node->appendToBody(getSuccessorsBody(node, innerLoop));
	node->appendToBody(getAssignsToPHINodes(innerLoop, node));

	auto continueStmt = EmptyStmt::create();
	continueStmt->setMetadata("continue -> " + getLabel(node));
	node->appendToBody(continueStmt);

	node->setBody(WhileLoopStmt::create(ConstBool::create(true), node->getBody()));

	node->deleteSucc(1);
	node->removeSucc(0);
	reducedLoops.insert(getLoopFor(node));

	node->addSuccessor(parentLoopHeader);
}

/**
* @brief Completely structures given CFG @a cfg using @c goto statements.
*
* @par Preconditions
*  - @a cfg is non-null
*/
void StructureConverter::structureByGotos(ShPtr<CFGNode> cfg) {
	PRECONDITION_NON_NULL(cfg);

	CFGNodeVector flattenedCFG;
	auto func = [&flattenedCFG](const auto &node) {
		flattenedCFG.push_back(node);
		return true;
	};

	auto loop = getLoopFor(cfg);
	if (loop) {
		BFSTraverseLoop(cfg, func);
	} else {
		BFSTraverse(cfg, func);
	}

	for (const auto &node: flattenedCFG) {
		auto switchInst = llvm::dyn_cast<llvm::SwitchInst>(node->getTerm());
		if (node->getSuccNum() > 0 && switchInst &&
				!hasItem(reducedSwitches, node->getLastBB())) {
			auto controlExpr = converter->convertValueToExpression(node->getCond());
			auto switchStmt = SwitchStmt::create(controlExpr);

			for (auto &caseIt: switchInst->cases()) {
				auto index = caseIt.getSuccessorIndex();
				if (node->getSuccNum() <= index) {
					continue;
				}

				auto cond = converter->convertConstantToExpression(caseIt.getCaseValue());
				auto succ = node->getSucc(index);
				auto gotoBody = getGotoForSuccessor(node, succ);
				switchStmt->addClause(cond, gotoBody);
			}

			switchStmt->addDefaultClause(getGotoForSuccessor(node, node->getSucc(0)));

			node->appendToBody(switchStmt);
			reducedSwitches.insert(node->getLastBB());
		} else if (node->getSuccNum() == 2) {
			auto cond = converter->convertValueToExpression(node->getCond());
			auto ifTrue = getGotoForSuccessor(node, node->getSucc(0));
			auto ifFalse = getGotoForSuccessor(node, node->getSucc(1));
			node->appendToBody(getIfStmt(cond, ifTrue, ifFalse));
		} else if (node->getSuccNum() == 1) {
			auto gotoBody = getGotoForSuccessor(node, node->getSucc(0));
			node->appendToBody(gotoBody);
		}

		while (node->getSuccNum() > 0) {
			node->removeSucc(0);
		}
	}
}

/**
* @brief Creates a new body of the given if clause @a clause.
*
* @param[in] node Given if statement node.
* @param[in] clause Given if clause node.
* @param[in] ifSuccessor Successor of the if statement.
*
* @par Preconditions
*  - all of @a node, @a clause and @a ifSuccessor are non-null
*/
ShPtr<Statement> StructureConverter::getIfClauseBody(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &clause, const ShPtr<CFGNode> &ifSuccessor) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(clause);
	PRECONDITION_NON_NULL(ifSuccessor);

	auto phiCopies = getAssignsToPHINodes(clause, ifSuccessor);
	auto body = Statement::mergeStatements(getSuccessorsBody(node, clause), phiCopies);
	addBranchMetadataToEndOfBodyIfNeeded(body, clause, ifSuccessor);
	return body;
}

/**
* @brief Creates a new body of the given if clause @a clause. The body of the
*        clause is cloned.
*
* @param[in] node Given if statement node.
* @param[in] clause Given if clause node.
* @param[in] ifSuccessor Successor of the if statement.
*
* @par Preconditions
*  - all of @a node, @a clause and @a ifSuccessor are non-null
*/
ShPtr<Statement> StructureConverter::getIfClauseBodyClone(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &clause, const ShPtr<CFGNode> &ifSuccessor) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(clause);
	PRECONDITION_NON_NULL(ifSuccessor);

	auto phiCopies = getAssignsToPHINodes(clause, ifSuccessor);
	auto body = Statement::mergeStatements(getSuccessorsBodyClone(node, clause), phiCopies);
	addBranchMetadataToEndOfBodyIfNeeded(body, clause, ifSuccessor);
	return body;
}

/**
* @brief Returns new @c if statement with the given condition @a cond and true
*        body @c trueBody and false body (else clause) @a falseBody.
*
* If the given @a trueBody contains only empty statements, the condition will be
* negated to produce non-empty body of the @c if statement.
*
* If the given @a falseBody ir nullptr or contains only empty statements,
* the else clause will be omitted.
*
* If both @a trueBody and @a falseBody contain only empty statements, nullptr
* will be returned.
*
* @par Preconditions
*  - both @a cond and @a falseBody are non-null
*/
ShPtr<IfStmt> StructureConverter::getIfStmt(const ShPtr<Expression> &cond,
		const ShPtr<Statement> &trueBody,
		const ShPtr<Statement> &falseBody) const {
	PRECONDITION_NON_NULL(cond);
	PRECONDITION_NON_NULL(trueBody);

	auto condition = cond;
	auto ifBody = trueBody;
	auto ifBodySkipped = skipEmptyStmts(ifBody);
	auto elseClause = falseBody;

	if (!ifBodySkipped && !skipEmptyStmts(elseClause)) {
		return nullptr;
	} else if (!ifBodySkipped) {
		condition = ExpressionNegater::negate(condition);
		std::swap(ifBody, elseClause);
	}

	auto ifStmt = IfStmt::create(condition, ifBody);
	if (skipEmptyStmts(elseClause)) {
		ifStmt->setElseClause(elseClause);
	}

	return ifStmt;
}

/**
* @brief Returns successor of the given loop node @a loopNode.
*
* Loop also could have no successor. In that case, nullptr is returned.
*
* @par Preconditions
*  - @a loopNode is non-null
*/
ShPtr<CFGNode> StructureConverter::getLoopSuccessor(
		const ShPtr<CFGNode> &loopNode) const {
	PRECONDITION_NON_NULL(loopNode);

	auto loop = getLoopFor(loopNode);
	return BFSFindFirst(loopNode, [this, loop](const auto &node) {
		return this->isInParentLoopOf(node, loop);
	});
}

/**
* @brief Completely reduces the given loop node @a loopNode.
*
* If loop cannot be reduced normally, it will be reduced by @c goto statements.
*
* @par Preconditions
*  - @a loopNode is non-null
*/
void StructureConverter::completelyReduceLoop(ShPtr<CFGNode> loopNode) {
	PRECONDITION_NON_NULL(loopNode);

	auto loop = getLoopFor(loopNode);
	auto func = [this](const auto &node) {
		return this->inspectCFGNode(node);
	};

	while (!hasItem(reducedLoops, loop) && BFSTraverse(loopNode, func)) {
		// Keep looping until the loop is reduced.
	}

	if (!hasItem(reducedLoops, loop)) {
		structureByGotos(loopNode);
		loopNode->addSuccessor(loopNode);
		reduceToWhileTrueLoop(loopNode);
	}
}

/**
* @brief Reduces node @a node into a node with the switch statement.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::reduceSwitchStatement(ShPtr<CFGNode> node) {
	PRECONDITION_NON_NULL(node);

	auto switchSuccessor = getSwitchSuccessor(node);
	auto hasDefault = hasDefaultClause(node, switchSuccessor);

	node->appendToBody(getSwitchStmt(node, switchSuccessor, hasDefault));

	removeReducedSuccsOfSwitch(node, hasDefault);
	reducedSwitches.insert(node->getLastBB());

	if (switchSuccessor) {
		node->addSuccessor(switchSuccessor);
	}
}

/**
* @brief Returns successor of the given switch node @a switchNode.
*
* Switch also could have no successor. In that case, nullptr is returned.
*
* @par Preconditions
*  - @a switchNode is non-null
*/
ShPtr<CFGNode> StructureConverter::getSwitchSuccessor(
		const ShPtr<CFGNode> &switchNode) const {
	PRECONDITION_NON_NULL(switchNode);

	return BFSFindFirst(switchNode, [this, &switchNode](const auto &node) {
		return this->isNodeAfterAllSwitchClauses(node, switchNode);
	});
}

/**
* @brief Determines whether the given node @a node is after all clauses of the
*        given switch @a switchNode.
*
* @par Preconditions
*  - both @a node and @a switchNode are non-null
*/
bool StructureConverter::isNodeAfterAllSwitchClauses(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &switchNode) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(switchNode);

	if (switchNode->hasSuccessor(node) && node != switchNode->getSucc(0)) {
		return false;
	}

	for (auto switchClause: switchNode->getSuccessors()) {
		if (!isNodeAfterSwitchClause(node, switchClause)) {
			return false;
		}
	}

	return true;
}

/**
* @brief Determines whether the given node @a node is after the given switch
*        clause @a clauseNode.
*
* @par Preconditions
*  - both @a node and @a clauseNode are non-null
*/
bool StructureConverter::isNodeAfterSwitchClause(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &clauseNode) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(clauseNode);

	if (node == clauseNode) {
		return true;
	} else if (existsPathWithoutLoopsBetween(node, clauseNode)) {
		return false;
	} else if (clauseNode->getSuccNum() == 0) {
		return true;
	}

	return existsPathWithoutLoopsBetween(clauseNode, node);
}

/**
* @brief Determines whether the given switch node @a switchNode has a default
*        clause.
*
* @param[in] switchNode Given switch node.
* @param[in] switchSuccessor Successor of the switch.
*
* @par Preconditions
*  - @a switchNode is non-null
*/
bool StructureConverter::hasDefaultClause(const ShPtr<CFGNode> &switchNode,
		const ShPtr<CFGNode> &switchSuccessor) const {
	PRECONDITION_NON_NULL(switchNode);

	return switchSuccessor != switchNode->getSucc(0);
}

/**
* @brief Determines whether the given switch clause @a clauseNode is a clause
*        ready to be reduced.
*
* Clause is ready to be reduced, when it is in one of these states:
*  - it terminates
*  - it falls through to the another clause
*  - it has only one successor which is the successor of the whole switch
*
* @param[in] clauseNode Given switch clause node.
* @param[in] switchNode Given switch node.
* @param[in] switchSuccessor Successor of the switch.
* @param[in] hasDefault Has switch default clause?
*
* @par Preconditions
*  - both @a clauseNode and @a switchNode are non-null
*/
bool StructureConverter::isReducibleClause(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode, const ShPtr<CFGNode> &switchSuccessor,
		bool hasDefault) const {
	PRECONDITION_NON_NULL(clauseNode);
	PRECONDITION_NON_NULL(switchNode);

	if (!hasOnlySwitchOrClausesInPreds(clauseNode, switchNode, hasDefault)) {
		return false;
	}

	if (clauseNode->getSuccNum() == 0) {
		return true;
	} else if (clauseNode->getSuccNum() == 1) {
		if (fallsThroughToAnotherCase(clauseNode, switchNode, hasDefault)) {
			return true;
		} else if (clauseNode->getSucc(0) == switchSuccessor) {
			return true;
		}
	}

	return false;
}

/**
* @brief Determines whether the given switch clause @a clauseNode has only
*        switch node or other clauses in predecessors.
*
* @param[in] clauseNode Given switch clause node.
* @param[in] switchNode Given switch node.
* @param[in] hasDefault Has switch default clause?
*
* @par Preconditions
*  - both @a clauseNode and @a switchNode are non-null
*/
bool StructureConverter::hasOnlySwitchOrClausesInPreds(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode, bool hasDefault) const {
	PRECONDITION_NON_NULL(clauseNode);
	PRECONDITION_NON_NULL(switchNode);

	for (const auto &pred: clauseNode->getPredecessors()) {
		if (pred == switchNode) {
			continue;
		}

		if (!hasDefault && pred == switchNode->getSucc(0)) {
			return false;
		} else if (!switchNode->hasSuccessor(pred)) {
			return false;
		}
	}

	return true;
}

/**
* @brief Determines whether the given switch clause @a clauseNode falls through
*        to the another case clause or to the default clause.
*
* @param[in] clauseNode Given switch clause node.
* @param[in] switchNode Given switch node.
* @param[in] hasDefault Has switch default clause?
*
* @par Preconditions
*  - both @a clauseNode and @a switchNode are non-null
*/
bool StructureConverter::fallsThroughToAnotherCase(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode, bool hasDefault) const {
	PRECONDITION_NON_NULL(clauseNode);
	PRECONDITION_NON_NULL(switchNode);

	if (clauseNode->getSuccNum() != 1) {
		return false;
	}

	auto clauseSuccessor = clauseNode->getSucc(0);
	if (!hasDefault && clauseSuccessor == switchNode->getSucc(0)) {
		return false;
	}

	return switchNode->hasSuccessor(clauseSuccessor);
}

/**
* @brief Returns new @c switch statement which is created from the given switch
*        node @a switchNode.
*
* @param[in] switchNode Given switch node.
* @param[in] switchSuccessor Successor of the switch.
* @param[in] hasDefault Has switch default clause?
*
* @par Preconditions
*  - @a switchNode is non-null
*/
ShPtr<SwitchStmt> StructureConverter::getSwitchStmt(const ShPtr<CFGNode> &switchNode,
		const ShPtr<CFGNode> &switchSuccessor, bool hasDefault) {
	PRECONDITION_NON_NULL(switchNode);

	auto controlExpr = converter->convertValueToExpression(switchNode->getCond());
	auto switchStmt = SwitchStmt::create(controlExpr);

	CFGNode::CFGNodeSet generated;
	auto clauses = getSwitchClauses(switchNode, hasDefault);
	auto sortedClauses = sortSwitchClauses(clauses, switchSuccessor);
	for (const auto &clause: sortedClauses) {
		auto body = getClauseBody(clause->second, switchNode, switchSuccessor, generated);
		addClausesWithTheSameCond(switchStmt, clause->first, body);
		generated.insert(clause->second);
		generatedNodes.insert(clause->second);
	}

	return switchStmt;
}

/**
* @brief Returns a vector of clauses of the given switch node @a switchNode.
*
* @param[in] switchNode Given switch node.
* @param[in] hasDefault Has switch default clause?
*
* @par Preconditions
*  - @a switchNode is non-null
*/
StructureConverter::SwitchClauseVector StructureConverter::getSwitchClauses(
		const ShPtr<CFGNode> &switchNode, bool hasDefault) const {
	PRECONDITION_NON_NULL(switchNode);

	CFGNode::CFGNodeVector nodesOrder;
	MapCFGNodeToSwitchClause mapNodeToClause;

	auto switchInst = llvm::cast<llvm::SwitchInst>(switchNode->getTerm());
	for (auto &caseIt: switchInst->cases()) {
		auto cond = converter->convertConstantToExpression(caseIt.getCaseValue());
		auto succ = switchNode->getSucc(caseIt.getSuccessorIndex());

		auto existingClauseIt = mapNodeToClause.find(succ);
		if (existingClauseIt != mapNodeToClause.end()) {
			auto existingClause = existingClauseIt->second;
			auto &clauseConds = existingClause->first;
			clauseConds.push_back(cond);
		} else {
			auto newClause = std::make_shared<SwitchClause>(
				ExprVector{cond}, succ);
			mapNodeToClause.emplace(succ, newClause);
			nodesOrder.push_back(succ);
		}
	}

	SwitchClauseVector clauses;
	for (const auto &clauseNode: nodesOrder) {
		clauses.push_back(mapNodeToClause[clauseNode]);
	}

	if (hasDefault) {
		auto defaultClause = std::make_shared<SwitchClause>(
			ExprVector{nullptr}, switchNode->getSucc(0));
		clauses.push_back(defaultClause);
	}

	return clauses;
}

/**
* @brief Returns sorted vector of switch clauses @a clauses.
*
* @param[in] clauses Switch clauses to be sorted.
* @param[in] switchSuccessor Successor of the switch.
*/
StructureConverter::SwitchClauseVector StructureConverter::sortSwitchClauses(
		const SwitchClauseVector &clauses,
		const ShPtr<CFGNode> &switchSuccessor) const {
	SwitchClauseVector unsorted(clauses);
	SwitchClauseVector sorted;
	CFGNode::CFGNodeSet used;

	MapCFGNodeToSwitchClause mapNodeToClause;
	for (const auto &clause: clauses) {
		mapNodeToClause.emplace(clause->second, clause);
	}

	while (!unsorted.empty()) {
		const auto clause = findFirstClauseWithSinglePred(unsorted);
		if (!clause) {
			break;
		}

		auto clauseIt = clause->second;
		while (clauseIt && clauseIt != switchSuccessor) {
			const auto currClause = mapNodeToClause[clauseIt];
			if (hasItem(used, clauseIt)) {
				break;
			}
			sorted.push_back(currClause);
			used.insert(clauseIt);
			removeItem(unsorted, currClause);

			clauseIt = clauseIt->getSuccOrNull(0);
		}
	}

	return sorted;
}

/**
* @brief Returns first switch clause from the vector of clauses @a clauses
*        which has only single predecessor.
*/
ShPtr<StructureConverter::SwitchClause> StructureConverter::findFirstClauseWithSinglePred(
		const SwitchClauseVector &clauses) const {
	for (const auto clause: clauses) {
		const auto clauseBody = clause->second;
		if (clauseBody->getPredsNum() == 1) {
			return clause;
		}
	}

	return nullptr;
}

/**
* @brief Returns new @c case clause of the @c switch statement which is created
*        from the given switch node @a clauseNode.
*
* @param[in] clauseNode Given switch clause node.
* @param[in] switchNode Given switch node.
* @param[in] switchSuccessor Successor of the switch.
* @param[in] generated Already generated switch clauses.
*
* @par Preconditions
*  - both @a clauseNode and @a switchNode are non-null
*/
ShPtr<Statement> StructureConverter::getClauseBody(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchNode, const ShPtr<CFGNode> &switchSuccessor,
		const CFGNode::CFGNodeSet &generated) {
	PRECONDITION_NON_NULL(clauseNode);
	PRECONDITION_NON_NULL(switchNode);

	auto body = getSuccessorsBody(switchNode, clauseNode);
	if (clauseNode->getSuccNum() == 0) {
		return body;
	}

	auto clauseSucc = clauseNode->getSucc(0);
	auto clauseSuccLabel = getLabel(clauseSucc);
	if (hasItem(generated, clauseSucc)) {
		auto gotoStmt = getGotoForSuccessor(clauseNode, clauseSucc);
		Statement::getLastStatement(gotoStmt)->setMetadata(
			"branch (via goto) -> " + clauseSuccLabel);
		body = Statement::mergeStatements(body, gotoStmt);
	} else if (isClauseTerminatedByBreak(clauseNode, switchSuccessor)) {
		auto breakStmt = BreakStmt::create();
		loopTargets.emplace(breakStmt, switchSuccessor);
		breakStmt->setMetadata("break -> " + clauseSuccLabel);
		body = Statement::mergeStatements(body, breakStmt);
	} else if (clauseNode->getSuccNum() == 1) {
		auto emptyStmt = EmptyStmt::create();
		emptyStmt->setMetadata("branch -> " + clauseSuccLabel);
		body = Statement::mergeStatements(body, emptyStmt);
	}

	return body;
}

/**
* @brief Determines whether the given switch clause @a clauseNode is terminated
*        by a break statement.
*
* @param[in] clauseNode Given switch clause node.
* @param[in] switchSuccessor Successor of the switch.
*
* @par Preconditions
*  - clauseNode is non-null
*/
bool StructureConverter::isClauseTerminatedByBreak(const ShPtr<CFGNode> &clauseNode,
		const ShPtr<CFGNode> &switchSuccessor) const {
	PRECONDITION_NON_NULL(clauseNode);

	return clauseNode->getSuccNum() == 1
		&& clauseNode->getSucc(0) == switchSuccessor;
}

/**
* @brief Adds @c case clauses with different conditions, but with the same
*        clause body to the given switch statement @a switchStmt.
*
* @param[out] switchStmt Given switch statement.
* @param[in] conds Given vector of conditions with the same clause body.
* @param[in] clauseBody Given clause clauseBody.
*
* @par Preconditions
*  - both @a switchStmt and @a clauseBody are non-null
*/
void StructureConverter::addClausesWithTheSameCond(ShPtr<SwitchStmt> switchStmt,
		const ExprVector &conds, const ShPtr<Statement> &clauseBody) const {
	PRECONDITION_NON_NULL(switchStmt);
	PRECONDITION_NON_NULL(clauseBody);

	for (std::size_t i = 0, e = conds.size() - 1; i < e; ++i) {
		switchStmt->addClause(conds[i], EmptyStmt::create());
	}

	switchStmt->addClause(conds.back(), clauseBody);
}

/**
* @brief Removes reduced successors of the given switch node @a switchNode.
*
* @param[in] switchNode Given switch node.
* @param[in] hasDefault Has switch default clause?
*
* @par Preconditions
*  - @a switchNode is non-null
*/
void StructureConverter::removeReducedSuccsOfSwitch(const ShPtr<CFGNode> &switchNode,
		bool hasDefault) const {
	PRECONDITION_NON_NULL(switchNode);

	if (hasDefault) {
		switchNode->deleteSuccessors();
	} else {
		auto i = switchNode->getSuccNum();
		while (i-- > 1) {
			switchNode->deleteSucc(i);
		}

		// The first successor of the switch statement cannot be deleted,
		// because it is the successor of the whole switch, which can
		// have its own successors.
		switchNode->removeSucc(0);
	}
}

/**
* @brief Creates a new body of the given node @a node successor @a succ.
*
* @par Preconditions
*  - both @a node and @a succ are non-null
*/
ShPtr<Statement> StructureConverter::getSuccessorsBody(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(succ);

	auto phiCopies = getAssignsToPHINodes(node, succ);
	return Statement::mergeStatements(phiCopies, succ->getBody());
}

/**
* @brief Creates a new body of the given node @a node successor @a succ.
*        The body of the successor is cloned.
*
* @par Preconditions
*  - both @a node and @a succ are non-null
*/
ShPtr<Statement> StructureConverter::getSuccessorsBodyClone(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &succ) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(succ);

	auto bodyClone = Statement::cloneStatements(succ->getBody());

	insertClonedLoopTargets(succ->getBody(), bodyClone);

	stmtClones[succ->getBody()].push_back(bodyClone);
	auto phiCopies = getAssignsToPHINodes(node, succ);
	return Statement::mergeStatements(phiCopies, bodyClone);
}

/**
* @brief Inserts cloned break/continue stmts in case they need replacing
*/
void StructureConverter::insertClonedLoopTargets(
		ShPtr<Statement> origParent, ShPtr<Statement> newParent) {

	auto origStmt = StructureConverter::findContinueOrBreakStatements(origParent,
		SwitchParent::No);
	auto newStmt = StructureConverter::findContinueOrBreakStatements(newParent,
		SwitchParent::No);
	auto num = origStmt.size();
	for (std::size_t i = 0; i < num; i++) {
		auto target = loopTargets.find(origStmt[i]);
		loopTargets.emplace(newStmt[i],target->second);
	}
}
/**
* @brief Finds break and continue statements in cloned statements
*/
std::vector<ShPtr<Statement>> StructureConverter::findContinueOrBreakStatements(
	ShPtr<Statement> parent, SwitchParent sp) {

	std::vector<ShPtr<Statement>> stmts;
	ShPtr<Statement> stmt = parent;

	while (stmt) {
		if (auto ifStmt = cast<IfStmt>(stmt)) {
			auto vec = findContinueOrBreakStatements(ifStmt->getFirstIfBody(), SwitchParent::No);
			stmts.insert(stmts.end(), vec.begin(), vec.end());
			vec = findContinueOrBreakStatements(ifStmt->getElseClause(), SwitchParent::No);
			stmts.insert(stmts.end(), vec.begin(), vec.end());
		} else if (auto switchStmt = cast<SwitchStmt>(stmt)) {
			for (auto clause = switchStmt->clause_begin();
					clause != switchStmt->clause_end(); ++clause) {
				auto vec = findContinueOrBreakStatements((*clause).second, SwitchParent::Yes);
				stmts.insert(stmts.end(), vec.begin(), vec.end());
			}
		} else {
			if ((isa<BreakStmt>(stmt) && sp != SwitchParent::Yes) || isa<ContinueStmt>(stmt)) {
				stmts.push_back(stmt);
			}
		}
		stmt = stmt->getSuccessor();
	}
	return stmts;
}

/**
* @brief Creates a @c goto statement which jumps from the given node @a node
*        to the given target node @a target.
*
* @par Preconditions
*  - both @a node and @a target are non-null
*/
ShPtr<Statement> StructureConverter::getGotoForSuccessor(const ShPtr<CFGNode> &node,
		const ShPtr<CFGNode> &target) {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(target);

	addGotoTargetIfNotExists(target);

	labelsHandler->setGotoTargetLabel(target->getBody(), target->getFirstBB());

	auto phiCopies = getAssignsToPHINodes(node, target);
	auto gotoStmt = GotoStmt::create(target->getBody());
	targetReferences[target].push_back(gotoStmt);
	return Statement::mergeStatements(phiCopies, gotoStmt);
}

/**
* @brief Returns assignments to the PHI nodes from the given node @a from and
*        to the given node @a to.
*
* @par Preconditions
*  - both @a from and @a to are non-null
*/
ShPtr<Statement> StructureConverter::getAssignsToPHINodes(const ShPtr<CFGNode> &from,
		const ShPtr<CFGNode> &to) {
	PRECONDITION_NON_NULL(from);
	PRECONDITION_NON_NULL(to);

	return getPHICopiesForSuccessor(from->getLastBB(), to->getFirstBB());
}

/**
* @brief Returns PHI copies for the given basic block @a currBB and its
*        successor @a succ.
*
* @par Preconditions
*  - both @a currBB and @a succ are non-null
*/
ShPtr<Statement> StructureConverter::getPHICopiesForSuccessor(
		llvm::BasicBlock *currBB, llvm::BasicBlock *succ) {
	PRECONDITION_NON_NULL(currBB);
	PRECONDITION_NON_NULL(succ);

	auto generatedPHINodesFromCurrBB = generatedPHINodes.find(currBB);
	if (generatedPHINodesFromCurrBB != generatedPHINodes.end()) {
		if (hasItem(generatedPHINodesFromCurrBB->second, succ)) {
			return nullptr;
		} else {
			generatedPHINodesFromCurrBB->second.insert(succ);
		}
	} else {
		generatedPHINodes.emplace(currBB, BBSet({succ}));
	}

	if (!LLVMSupport::isPredecessorOf(currBB, succ)) {
		return nullptr;
	}

	ShPtr<Statement> phiCopies;
	for (auto i = succ->begin(); llvm::isa<llvm::PHINode>(i); ++i) {
		auto pn = llvm::cast<llvm::PHINode>(i);
		auto val = pn->getIncomingValueForBlock(currBB);
		if (llvm::isa<llvm::UndefValue>(val)) {
			continue;
		}

		auto loop = loopInfo->getLoopFor(succ);
		if (loop && canBeForLoop(loop) && loop->getCanonicalInductionVariable() == pn) {
			continue;
		}

		auto lhs = converter->convertValueToVariable(&*i);
		auto rhs = converter->convertValueToExpression(val);
		auto phiCopy = AssignStmt::create(lhs, rhs);
		phiCopies = Statement::mergeStatements(phiCopies, phiCopy);
	}

	return phiCopies;
}

/**
* @brief Initializes required LLVM analyses for converted function @a func.
*/
void StructureConverter::initialiazeLLVMAnalyses(llvm::Function &func) {
	loopInfo = &basePass->getAnalysis<llvm::LoopInfoWrapperPass>(func).getLoopInfo();
	scalarEvolution = &basePass->getAnalysis<llvm::ScalarEvolutionWrapperPass>(func).getSE();
}

/**
* @brief Returns the innermost loop for the given node @a node. If node is not
*        inside loop, returns nulptr.
*
* @par Preconditions
*  - @a node is non-null
*/
llvm::Loop *StructureConverter::getLoopFor(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	auto loopIt = loopInfo->getLoopFor(node->getFirstBB());
	while (loopIt && hasItem(reducedLoops, loopIt)) {
		loopIt = loopIt->getParentLoop();
	}

	return loopIt;
}

/**
* @brief Determines whether the given node @a node is a loop header.
*
* @par Preconditions
*  - @a node is non-null
*/
bool StructureConverter::isLoopHeader(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	auto loop = loopInfo->getLoopFor(node->getFirstBB());
	if (loop && hasItem(reducedLoops, loop)) {
		return false;
	}

	return loopInfo->isLoopHeader(node->getFirstBB());
}

/**
* @brief Determines whether the given node @a node is a header of the given loop
*        @a loop.
*
* @par Preconditions
*  - both @a node and @a loop are non-null
*/
bool StructureConverter::isLoopHeader(const ShPtr<CFGNode> &node,
		llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(loop);

	return isLoopHeader(node) && getLoopFor(node) == loop;
}

/**
* @brief Determines whether the given node @a node is outside of the given loop
*        @a loop.
*
* @par Preconditions
*  - both @a node and @a loop are non-null
*/
bool StructureConverter::isNodeOutsideLoop(const ShPtr<CFGNode> &node,
		llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(loop);

	return !loop->contains(getLoopFor(node));
}

/**
* @brief Determines whether the given node @a node is in the parent loop of the
*        given loop @a loop.
*
* This method returns @c true also if @a loop does not have a parent and @a node
* is outside @a loop.
*
* @par Preconditions
*  - both @a node and @a loop are non-null
*/
bool StructureConverter::isInParentLoopOf(const ShPtr<CFGNode> &node,
		llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(node);
	PRECONDITION_NON_NULL(loop);

	if (!isNodeOutsideLoop(node, loop)) {
		return false;
	}

	auto parentLoop = loop->getParentLoop();
	if (!parentLoop) {
		return true;
	}

	return getLoopFor(node) == parentLoop;
}

/**
* @brief Returns number of iterations for the given @c for loop @a loop. If
*        @a loop is not a @c for loop, it returns zero.
*
* @par Preconditions
*  - @a loop is non-null
*/
unsigned StructureConverter::getTripCount(llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(loop);

	return scalarEvolution->getSmallConstantTripCount(loop);
}

/**
* @brief Determines whether the given loop @a loop can be a @c for loop.
*
* Loop can be a @c for loop when it has the induction variable and non-zero
* number of iterations.
*
* @par Preconditions
*  - @a loop is non-null
*/
bool StructureConverter::canBeForLoop(llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(loop);

	auto inductionVar = loop->getCanonicalInductionVariable();
	auto tripCount = getTripCount(loop);

	return inductionVar && tripCount > 0;
}

/**
* @brief Adds node @a node to the vector of the goto targets if
*        it isn't already there.
*
* @par Preconditions
*  - @a node is non-null
*/
void StructureConverter::addGotoTargetIfNotExists(
		const ShPtr<CFGNode> &node) {
	PRECONDITION_NON_NULL(node);

	if (!hasItem(gotoTargetsSet, node)) {
		gotoTargets.push_back(node);
		gotoTargetsSet.insert(node);
	}
}

/**
* @brief Adds metadata of the form "branch -> xxx" to the @a body of the given
*        if statement (if needed).
*/
void StructureConverter::addBranchMetadataToEndOfBodyIfNeeded(ShPtr<Statement> &body,
		const ShPtr<CFGNode> &clause, const ShPtr<CFGNode> &ifSuccessor) const {
	if (clause->getSuccNum() == 1 && clause->getSucc(0) == ifSuccessor) {
		auto emptyStmt = EmptyStmt::create();
		emptyStmt->setMetadata("branch -> " + getLabel(ifSuccessor));
		body = Statement::mergeStatements(body, emptyStmt);
	}
}

/**
* @brief Returns a label of the given node @a node.
*
* @par Preconditions
*  - @a node is non-null
*/
std::string StructureConverter::getLabel(const ShPtr<CFGNode> &node) const {
	PRECONDITION_NON_NULL(node);

	return labelsHandler->getLabel(node->getFirstBB());
}

/**
* @brief Cleans up the helper containers.
*/
void StructureConverter::cleanUp() {
	loopHeaders.clear();
	generatedPHINodes.clear();
	reducedLoops.clear();
	reducedSwitches.clear();
	statementsStack = CFGNodeStack();
	statementsOnStack.clear();
	gotoTargets.clear();
	gotoTargetsSet.clear();
	generatedNodes.clear();
	loopTargets.clear();
	targetReferences.clear();
	stmtClones.clear();
}

} // namespace llvmir2hll
} // namespace retdec
